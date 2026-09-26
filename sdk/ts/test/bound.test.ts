// Pool V3 and bound wallets in the TypeScript layer (docs/account-bound-note-spec.md §6–§10): the
// pinned parameters and verifier kind, pending proposals and the deposit rule, the setup checks, and
// a bound full withdrawal end to end: a stale plan, the V5 proof, the account's authorization
// (checked against starknet.js's own SNIP-12 hash), the free-withdrawal payment, the job body, a
// server returning another pool call, the owner-submit refusal, submission and the expiry rule.
import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { typedData } from 'starknet';
import { beforeAll, describe, expect, test } from 'vitest';

import * as wasm from '../wasm/templar.js';
import initTest, * as twasm from '../wasm-test/templar_test.js';
import { BOUND_ACCOUNT_CLASSES, KIND_R0, MemoryKV, SEPOLIA, Templar, canon, loadCore, pinsOf, type BoundSigner, type NetworkConstants } from '../dist/index.js';
import { MockChain, MockProver, type MockAccount, SEPOLIA_V2 } from './mockchain.js';

const TOKEN = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
const A = '0x7a11ce00000000000000000000000000000000000000000000000000000a11';
/** The R0 V5 client circuit (the cairo-r5 bridge's build record). */
const V5_CIRCUIT = [1903585510, 1708577544, 3915427995, 3101166941, 461832048, 2805149134, 1077751030, 1205594117];

const V3: NetworkConstants = {
  ...SEPOLIA,
  pools: [
    {
      ...SEPOLIA.pools[0]!,
      pool: '0x7e57b301',
      version: 'v5',
      parameters: { expiryWindow: 1500, quantum: 100, rootWindow: 4096, timelock: 86400 },
      adapter: '0xada5',
      adapterClass: '0xada5c1a5',
      statement: '0x5a7e05',
      statementClass: '0x5a7e05c1a5',
      accountTag: 'TMPZR0_PAYMENT_V5',
      maxProofAge: 1024,
      circuitHash: V5_CIRCUIT,
    },
  ],
};
const POOL = V3.pools[0]!;
const [ARGENT, BRAAVOS] = BOUND_ACCOUNT_CLASSES as [(typeof BOUND_ACCOUNT_CLASSES)[0], (typeof BOUND_ACCOUNT_CLASSES)[0]];

/** A wallet that "signs" with starknet.js's SNIP-12 hash of the typed data it is given. */
function signer(account = A, seen: object[] = []): BoundSigner {
  return { address: account, signTypedData: async (td) => (seen.push(td), [typedData.getMessageHash(td as any, account), '0x1']) };
}

/** An account whose `is_valid_signature` accepts exactly `[hash, 1]`. */
function argent(views: Record<string, string[]> = { get_guardian: ['0x0'], get_guardian_guid: ['0x1'] }): MockAccount {
  return { classHash: ARGENT.classHash, views, valid: (h, sig) => sig.length === 2 && BigInt(sig[0]!) === BigInt(h) && BigInt(sig[1]!) === 1n };
}

async function setup(network: NetworkConstants = V3) {
  const chain = new MockChain(network.pools[0]!);
  const kv = new MemoryKV();
  const t = await Templar.connect({ provider: chain.provider(), network, kv });
  return { chain, kv, t };
}

function depositTo(chain: MockChain, address: string, amount: bigint) {
  chain.deposit(JSON.parse(wasm.note_for(address, TOKEN, amount.toString(), V3.chainId, POOL.pool)), TOKEN, amount);
}

function mockProver(chain: MockChain) {
  const pins = JSON.stringify(pinsOf(V3, POOL));
  return new MockProver(chain, (binding, base, hash) => JSON.parse(twasm.test_expected_facts(pins, binding, BigInt(base), hash)));
}

beforeAll(async () => {
  await loadCore();
  await initTest({ module_or_path: readFileSync(new URL('../wasm-test/templar_test_bg.wasm', import.meta.url)) });
});

describe('pool V3', () => {
  test('pinned parameters, the verifier by kind, proposals and the deposit rule', async () => {
    const { chain, t } = await setup();
    expect(chain.calls.some((c) => c.method === 'callContract' && c.args[1] === 'get_parameters')).toBe(true);
    const gv = chain.calls.find((c) => c.method === 'callContract' && c.args[1] === 'get_verifier')!;
    expect(gv.args[2]).toEqual([KIND_R0]);
    // Parameters other than the pinned ones are refused, the timelock included (AB-SP15).
    for (const params of [['0x5dc', '0x32', '0x1000', '0x15180'], ['0x5dc', '0x64', '0x1000', '0x1']]) {
      const other = new MockChain(POOL);
      other.parameters = params;
      await expect(Templar.connect({ provider: other.provider(), network: V3, kv: new MemoryKV() })).rejects.toThrow(/pin_mismatch/);
    }
    // On SN_MAIN, a timelock under 7 days is refused even when pinned.
    const MAIN = { ...V3, chainId: '0x534e5f4d41494e' };
    const onMain = new MockChain(POOL);
    const mainProvider = { ...onMain.provider(), getChainId: async () => MAIN.chainId };
    await expect(Templar.connect({ provider: mainProvider as any, network: MAIN, kv: new MemoryKV() })).rejects.toThrow(/mainnet floors/);

    const w = await t.wallet(new Uint8Array(32).fill(0xc3));
    expect(await w.proposals()).toEqual([]);
    const deposit = () => w.deposit(chain.account(), { asset: { standard: 20, contract: TOKEN }, amount: 50n });
    // A pending verifier change stops deposits (AB-PV2), before anything is sent.
    chain.proposals.set(KIND_R0, ['0xbad', 1_900_000_000]);
    expect(await w.proposals()).toMatchObject([{ key: KIND_R0, value: '0xbad', eta: 1_900_000_000, lapsesAt: 1_900_086_400, lapsed: false, verifier: true }]);
    await expect(deposit()).rejects.toThrow(/verifier_change_pending/);
    expect(chain.sent.length).toBe(0);
    // Past eta + T it lapses: shown, but it blocks nothing (AB-SP15).
    chain.timestamp = 1_900_086_401;
    expect(await w.proposals()).toMatchObject([{ key: KIND_R0, lapsed: true }]);
    expect((await deposit()).confirmed).toBe(true);
    chain.timestamp = 1_800_000_000;
    // A shadow-class change is shown, but does not stop deposits.
    chain.proposals.delete(KIND_R0);
    chain.proposals.set('0xc1a55', ['0x1', 1_900_000_000]);
    expect(await w.proposals(['0xc1a55'])).toMatchObject([{ key: '0xc1a55', verifier: false }]);
    const d = await deposit();
    expect(d.confirmed).toBe(true);
    // A bound wallet's 60-byte keys never open as a Templar wallet (AB-SP19).
    await expect(t.wallet(new Uint8Array(60))).rejects.toThrow(/bad_seed/);
  }, 60_000);
});

describe('bound wallets', () => {
  test('seeds: 28 bytes and 21 words, never confused with a Templar wallet', () => {
    const seed = Templar.generateBoundSeed();
    expect(seed.length).toBe(28);
    const words = Templar.boundMnemonic(seed);
    expect(words.split(' ').length).toBe(21);
    expect([...Templar.boundSeedFromMnemonic(words)]).toEqual([...seed]);
    const templar24 = Templar.mnemonic(Templar.generateSeed());
    expect(() => Templar.boundSeedFromMnemonic(templar24)).toThrow();
    expect(() => Templar.seedFromMnemonic(words)).toThrow();
  });

  test('setup checks: the pool, the class matrix, signers, and the account signature rules', async () => {
    const onV2 = await (async () => {
      const chain = new MockChain();
      return Templar.connect({ provider: chain.provider(), network: SEPOLIA_V2, kv: new MemoryKV() });
    })();
    await expect(onV2.boundSetupCheck(A, signer())).rejects.toThrow(/wrong_relation/);
    await expect(onV2.boundWallet(Templar.generateBoundSeed(), A, signer(), { spendProvider: new MockChain().provider() })).rejects.toThrow(/wrong_relation/);

    const { chain, t } = await setup();
    await expect(t.boundSetupCheck(A, signer())).rejects.toThrow(/account_not_deployed/);
    chain.accounts.set(canon(A), { ...argent(), classHash: '0x1234' });
    await expect(t.boundSetupCheck(A, signer())).rejects.toThrow(/account_class/);
    chain.accounts.set(canon(A), argent({ get_guardian: ['0x7'], get_guardian_guid: ['0x1'] }));
    await expect(t.boundSetupCheck(A, signer())).rejects.toThrow(/account_signers/);
    chain.accounts.set(canon(A), { ...argent(), classHash: BRAAVOS.classHash, views: { get_multisig_threshold: ['0x2'], get_signers: ['0x1', '0x9', '0x0', '0x0'] } });
    await expect(t.boundSetupCheck(A, signer())).rejects.toThrow(/account_signers/);
    // A wallet that signs something else; an account that accepts anything; a wallet connected to
    // another account (AB-SP16).
    chain.accounts.set(canon(A), argent());
    await expect(t.boundSetupCheck(A, signer('0x1234'))).rejects.toThrow(/account_mismatch/);
    const wrong: BoundSigner = { address: A, signTypedData: async () => ['0x1234', '0x1'] };
    await expect(t.boundSetupCheck(A, wrong)).rejects.toThrow(/setup_signature/);
    chain.accounts.set(canon(A), { ...argent(), valid: () => true });
    await expect(t.boundSetupCheck(A, signer())).rejects.toThrow(/setup_signature/);
    // Both launch classes pass; the setup message can never authorize a spend (pool 0).
    const seen: object[] = [];
    chain.accounts.set(canon(A), argent());
    expect(await t.boundSetupCheck(A, signer(A, seen))).toEqual({ vendor: ARGENT.vendor, version: ARGENT.version });
    const td = seen[0] as { domain: { version: string }; message: { pool: string } };
    expect(td.domain.version).toBe('V5');
    expect(td.message.pool).toBe('0x0');
    chain.accounts.set(canon(A), { ...argent(), classHash: BRAAVOS.classHash, views: { get_multisig_threshold: ['0x0'], get_signers: ['0x1', '0x9', '0x0', '0x0'] } });
    expect(await t.boundSetupCheck(A, signer())).toEqual({ vendor: BRAAVOS.vendor, version: BRAAVOS.version });
    // Spend reads need a provider that has not seen the account (spec §10), on the same chain.
    await expect(t.boundWallet(Templar.generateBoundSeed(), A, signer(), { spendProvider: t.provider })).rejects.toThrow(/spend_provider/);
    const elsewhere = { ...chain.provider(), getChainId: async () => '0x534e5f4d41494e' };
    await expect(t.boundWallet(Templar.generateBoundSeed(), A, signer(), { spendProvider: elsewhere as any })).rejects.toThrow(/another chain/);
    await expect(t.boundWallet(Templar.generateBoundSeed(), A, signer('0x99'), { spendProvider: chain.provider() })).rejects.toThrow(/account_mismatch/);
    // Opening re-runs the class and signer checks: after a guardian is added the wallet still opens
    // and syncs, but creates no address or deposit.
    chain.accounts.set(canon(A), argent({ get_guardian: ['0x7'], get_guardian_guid: ['0x1'] }));
    const guarded = await t.boundWallet(Templar.generateBoundSeed(), A, signer(), { spendProvider: chain.provider() });
    expect(guarded.accountIssue?.code).toBe('account_signers');
    expect((await guarded.sync()).complete).toBe(true);
    await expect(guarded.address(0)).rejects.toThrow(/account_signers/);
    await expect(guarded.deposit(chain.account('0xacc'), { asset: { standard: 20, contract: TOKEN }, amount: 1n, to: '0x1' })).rejects.toThrow(/account_signers/);
    // A node that fails to answer the signature check fails the setup check (not a refusal).
    chain.accounts.set(canon(A), { ...argent(), valid: () => { throw new Error('socket hang up'); } });
    await expect(t.boundSetupCheck(A, signer())).rejects.toThrow(/rpc_unavailable/);
  }, 60_000);

  test('a bound full withdrawal: stale plan, prove, authorize, free payment, wrap, submit, expiry', async () => {
    const { chain, t } = await setup();
    chain.accounts.set(canon(A), argent());
    const seen: object[] = [];
    const w = await t.boundWallet(Templar.generateBoundSeed(), A, signer(A, seen), { spendProvider: chain.provider() });
    expect(w.boundAccount).toBe(canon(A));
    const addr = (await w.address(0)).address;
    depositTo(chain, addr, 1000n);
    chain.mine(12);
    expect((await w.sync()).balances).toMatchObject([{ asset: TOKEN, unspent: 1000n, spendable: 1000n }]);

    // A plan the chain has moved past can no longer land: the core refuses to prove it (AB-SM4).
    let spend = await w.withdraw(TOKEN, 1000n, '0xb0b');
    chain.mine(1601);
    await expect(spend.prove()).rejects.toThrow(/stale_plan/);
    spend = await w.withdraw(TOKEN, 1000n, '0xb0b');
    const plan = await spend.plan();
    expect(plan.version).toBe('v5');
    expect(plan.valid_until).toBe(Math.ceil((chain.latest + 1500) / 100) * 100);
    expect(canon(plan.bound_account!)).toBe(canon(A));

    const proved = await spend.prove();
    expect(proved.circuit_hash).toEqual(V5_CIRCUIT);
    expect(canon(proved.statement.account)).toBe(canon(A));

    // The account refuses: nothing is stored, and the wallet is asked again.
    const valid = chain.accounts.get(canon(A))!.valid;
    chain.accounts.get(canon(A))!.valid = () => false;
    await expect(spend.authorize()).rejects.toThrow(/signature_refused/);
    expect((await spend.record()).authorization).toBeUndefined();
    chain.accounts.get(canon(A))!.valid = valid;
    // The account accepts the signature over the core's hash, which is starknet.js's hash of the
    // core's typed data (the mock signer signs starknet.js's).
    const auth = await spend.authorize();
    const td = seen.at(-1) as { domain: { chainId: string }; message: Record<string, string> };
    expect(td.domain.chainId).toBe('SN_SEPOLIA');
    expect(td.message).toMatchObject({ pool: canon(POOL.pool), token_out: canon(TOKEN), withdrawal_recipient: '0xb0b', withdrawal_amount: '1000', intent: '0x0' });
    expect(auth.hash).toBe(canon(typedData.getMessageHash(td as any, A)));
    expect(await spend.authorize()).toEqual(auth);

    // A full withdrawal is free: both outputs open to zero-value notes.
    const payment = (await spend.freeWithdrawalPayment()) as { free_full_withdrawal: { openings: number[][] } };
    expect(payment.free_full_withdrawal.openings.map((o) => o.length)).toEqual([9, 9]);

    // A prover server publishing another spend message is refused (AB-SP19).
    const liar = mockProver(chain);
    liar.domain = { ...liar.domain, spend_type_hash: '0x1' };
    await expect(t.prover({ url: 'http://q', fetch: liar.fetch as any }).info()).rejects.toThrow(/prover_mismatch/);

    // A server that returns another pool call is refused; the honest result is then taken.
    const prover = mockProver(chain);
    prover.binding = proved.binding;
    const client = t.prover({ url: 'http://p', fetch: prover.fetch as any });
    prover.poolCall = (c: any) => ({ ...c, calldata: c.calldata.map((x: string, i: number) => (i === 5 ? '0x1' : x)) });
    await expect(spend.wrap(client, { url: 'http://p', payment })).rejects.toThrow(/bad_result/);
    prover.poolCall = undefined;
    const win = await spend.wrap(client, { url: 'http://p', payment });
    expect(prover.bodies.length).toBe(1);
    const body = JSON.parse(prover.bodies[0]!);
    expect(body).toMatchObject({ relation: 'r5', salt: auth.salt, signature: auth.signature, payment, pool_call: { entry_point: 'apply_spend', calldata: proved.calldata } });
    expect(canon(body.statement.account)).toBe(canon(A));
    const base = chain.latest - 1;
    expect(win.valid_until).toBe(Math.min(plan.valid_until!, base + POOL.maxProofAge));

    // The bound account never submits its own spend, nor anyone through the provider that has seen
    // A (AB-SP13); another account through another provider does.
    chain.mine(12);
    await expect(spend.submit(chain.account(A), { confirmFee: () => true })).rejects.toThrow(/owner_submits/);
    await expect(spend.submit({ ...chain.account('0xacc'), provider: t.provider }, { confirmFee: () => true })).rejects.toThrow(/spend_provider/);
    const sent = await spend.submit(chain.account('0xacc'), { confirmFee: () => true });
    expect(sent.transactionHash).toBe('0xbeef');

    // Near the statement's own expiry, another job cannot help: wrap asks for a re-plan (AB-SP18).
    chain.mine(plan.valid_until! - chain.latest - 10);
    await expect(spend.wrap(client, { url: 'http://p', payment })).rejects.toThrow(/replan/);
    // The transaction never lands: past `valid_until` by DEPTH blocks the record is dead.
    chain.mine(plan.valid_until! - chain.latest + 9);
    await w.sync();
    expect((await spend.record()).stage).not.toBe('dead');
    chain.mine(1);
    await w.sync();
    expect(await spend.record()).toMatchObject({ stage: 'dead', closed: 'expired' });
    // A closed record never prompts the wallet (AB-SP17).
    const prompts = seen.length;
    await expect(spend.authorize({ fresh: true })).rejects.toThrow(/record_closed/);
    expect(seen.length).toBe(prompts);
  }, 300_000);

  test('a re-plan or a signature refusal is authorized afresh, never with a stale signature', async () => {
    const { chain, t } = await setup();
    chain.accounts.set(canon(A), argent());
    const seen: object[] = [];
    const w = await t.boundWallet(Templar.generateBoundSeed(), A, signer(A, seen), { spendProvider: chain.provider() });
    depositTo(chain, (await w.address(0)).address, 500n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 500n, '0xb0b');
    const proved = await spend.prove();
    const first = await spend.authorize();
    // The server refuses the signature (403): the stored body is dropped, and a fresh
    // authorization of the same statement makes a new body (AB-SP12, AB-SP18).
    const prover = mockProver(chain);
    prover.binding = proved.binding;
    const fetch403 = async (u: string | URL, i?: { method?: string; body?: string }) =>
      String(u).endsWith('/v1/jobs') && i?.method === 'POST' ? new Response(JSON.stringify({ error: 'signature: authorize again' }), { status: 403 }) : prover.fetch(u, i);
    await expect(spend.wrap(t.prover({ url: 'http://p', fetch: fetch403 as any }), { url: 'http://p' })).rejects.toThrow(/prover_forbidden/);
    // A class the server does not serve is told apart: re-authorizing cannot help there.
    const fetchClass = async (u: string | URL, i?: { method?: string; body?: string }) =>
      String(u).endsWith('/v1/jobs') && i?.method === 'POST' ? new Response(JSON.stringify({ error: 'class', reason: 'account_class' }), { status: 403 }) : prover.fetch(u, i);
    await expect(spend.wrap(t.prover({ url: 'http://p', fetch: fetchClass as any }), { url: 'http://p' })).rejects.toThrow(/prover_account_class/);
    expect((await spend.record()).server).toBeUndefined();
    const prompts = seen.length;
    const second = await spend.authorize({ fresh: true });
    expect(seen.length).toBe(prompts + 1);
    expect(second.salt).not.toBe(first.salt);
    const rec = await spend.record();
    expect(rec.attempts.at(-1)!.authorization).toEqual(first);
    await spend.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p' });
    expect(JSON.parse(prover.bodies.at(-1)!).signature).toEqual(second.signature);
    // A re-plan clears the authorization; the new statement must be signed again before it leaves.
    const again = await w.replan(spend.id, { kind: 'withdraw', asset: TOKEN, amount: '500', recipient: '0xb0c' });
    expect((await again.record()).authorization).toBeUndefined();
    const reproved = await again.prove();
    await expect(again.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p' })).rejects.toThrow(/authorized before it leaves/);
    const third = await again.authorize();
    expect(seen.length).toBe(prompts + 2);
    expect(third.hash).not.toBe(second.hash);
    prover.binding = reproved.binding;
    await again.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p' });
    expect(JSON.parse(prover.bodies.at(-1)!).salt).toBe(third.salt);
  }, 300_000);

  test('a partial withdrawal has no free payment', async () => {
    const { chain, t } = await setup();
    const w = await t.wallet(new Uint8Array(32).fill(0xd4));
    depositTo(chain, (await w.address(0)).address, 10n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 4n, '0xb0b');
    expect(await spend.freeWithdrawalPayment()).toBeUndefined();
    await expect(spend.authorize()).rejects.toThrow(/not_bound/);
  }, 60_000);
});

test('Sepolia pins pool V3 as the active pool, with pool V2 kept as history', () => {
  const [v2, v3] = SEPOLIA.pools;
  expect(SEPOLIA.pools.length).toBe(2);
  expect(v2!.version ?? 'v4').toBe('v4');
  expect(v3!.version).toBe('v5');
  expect(v3!.accountTag).toBe('TMPZR0_PAYMENT_V5');
  expect(v3!.maxProofAge).toBe(1024);
  const { expiryWindow: E, quantum: Q, rootWindow: W, timelock: T } = v3!.parameters!;
  expect(W).toBeGreaterThanOrEqual(E + Q);
  expect(T).toBeGreaterThan(0);
  expect(v3!.deploymentBlock).toBeGreaterThan(v2!.deploymentBlock);
});
