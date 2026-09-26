// Sending a proof-carrying spend (spec §9.2): the raw fee estimate, fixed margins and a zero tip,
// the exact signed transaction simulated with validation at `pre_confirmed`, then that same object
// sent. Every call goes through the submitting account's own provider.
import { ETransactionVersion3, TransactionType, type Account, type Call } from 'starknet';

import { fail } from './errors.js';

type SignedInvoke = Awaited<ReturnType<Account['getSignedTransaction']>>;

/** Fixed multipliers over the raw estimate, identical for every wallet (spec §9.2, SDK-P10). */
export const AMOUNT_MARGIN_NUM = 3n;
export const AMOUNT_MARGIN_DEN = 2n;
export const PRICE_MARGIN = 2n;

export interface ResourceBounds {
  l1_gas: { max_amount: bigint; max_price_per_unit: bigint };
  l1_data_gas: { max_amount: bigint; max_price_per_unit: bigint };
  l2_gas: { max_amount: bigint; max_price_per_unit: bigint };
}

interface RawEstimate {
  l1_gas_consumed: string;
  l1_gas_price: string;
  l1_data_gas_consumed: string;
  l1_data_gas_price: string;
  l2_gas_consumed: string;
  l2_gas_price: string;
  overall_fee: string;
}

/** Bounds from a raw estimate: amount × 1.5 (rounded up), price × 2. */
export function boundsFrom(e: RawEstimate): { bounds: ResourceBounds; maxFee: bigint; expectedFee: bigint } {
  const amount = (x: string) => (BigInt(x) * AMOUNT_MARGIN_NUM + AMOUNT_MARGIN_DEN - 1n) / AMOUNT_MARGIN_DEN;
  const price = (x: string) => BigInt(x) * PRICE_MARGIN;
  const bounds: ResourceBounds = {
    l1_gas: { max_amount: amount(e.l1_gas_consumed), max_price_per_unit: price(e.l1_gas_price) },
    l1_data_gas: { max_amount: amount(e.l1_data_gas_consumed), max_price_per_unit: price(e.l1_data_gas_price) },
    l2_gas: { max_amount: amount(e.l2_gas_consumed), max_price_per_unit: price(e.l2_gas_price) },
  };
  const maxFee = Object.values(bounds).reduce((s, b) => s + b.max_amount * b.max_price_per_unit, 0n);
  return { bounds, maxFee, expectedFee: BigInt(e.overall_fee) };
}

export interface Prepared {
  signed: SignedInvoke;
  bounds: ResourceBounds;
  maxFee: bigint;
  expectedFee: bigint;
  nonce: string;
}

/**
 * Estimates, signs and simulates the exact transaction; nothing is sent. `nonce`: the relayer's
 * own sequence (several transactions per block); a wallet leaves it to the account.
 */
export async function prepare(account: Account, call: Call, proof: string, proofFacts: string[], opts: { nonce?: bigint } = {}): Promise<Prepared> {
  const provider = account.provider as unknown as { channel: { getEstimateFee: Function; fetch: Function } };
  const nonce = opts.nonce !== undefined ? { nonce: opts.nonce } : {};
  const invocations = await account.accountInvocationsFactory(
    [{ type: TransactionType.INVOKE, payload: [call] }],
    // The query version: the estimate is never a valid V3 transaction (SDK-IP9).
    { versions: [ETransactionVersion3.F3], skipValidate: false, tip: 0, proof, proofFacts, ...nonce },
  );
  const estimates = (await provider.channel.getEstimateFee(invocations, { skipValidate: false, blockIdentifier: 'pre_confirmed' })) as RawEstimate[];
  const raw = estimates[0];
  if (!raw) fail('estimate', 'no fee estimate');
  const { bounds, maxFee, expectedFee } = boundsFrom(raw);
  const signed = await account.getSignedTransaction([call], { resourceBounds: bounds, tip: 0, proof, proofFacts, ...nonce });
  const response = (await provider.channel.fetch('starknet_simulateTransactions', {
    block_id: 'pre_confirmed',
    transactions: [signed],
    simulation_flags: [],
  })) as Response;
  const sim = (await response.json()) as { result?: { transaction_trace: { execute_invocation: { revert_reason?: string } } }[]; error?: { message: string; data?: unknown } };
  if (sim.error) fail('simulation', `${sim.error.message} ${JSON.stringify(sim.error.data ?? '').slice(0, 400)}`);
  const trace = sim.result?.[0]?.transaction_trace;
  if (!trace) fail('simulation', 'no trace');
  if (trace.execute_invocation.revert_reason) fail('simulation_reverted', trace.execute_invocation.revert_reason.slice(0, 400));
  return { signed, bounds, maxFee, expectedFee, nonce: String(signed.nonce) };
}

/** Sends the exact prepared object through the account's own provider. */
export async function send(account: Account, p: Prepared): Promise<string> {
  const r = await account.provider.invokeSignedTx(p.signed);
  return r.transaction_hash;
}
