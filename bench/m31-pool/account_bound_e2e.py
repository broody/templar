"""R0 V5 against M31 pool V3 with the real statement account (`docs/account-bound-note-spec.md`
§15 P3b), in snforge:

  deposits: a 1000-unit ERC20 note bound to account A, and a 500-unit ordinary note
  S1  R0 V5, bound: A's note (one input + dummy) pays 400 to a recipient, 600 change + a dummy output
  S2  R0 V5, ordinary: the 500 note splits 300 + 200 (both proved against the tree after the
      deposits, so S2 lands on a replaced root inside the window)
    -> each proof: `wallet prove5`, then the statement account (its bridge verifies the proof; for
       S1 a mock account at A accepts only starknet.js's SNIP-12 hash and the fixture signature),
       its message as the V5 adapter's proof facts, and pool V3 recomputing the binding

The virtual OS and PROOF2 are P5. This assembles `pool_e2e` in a built bridge work directory
(`client-port/build_bridge_arith.py`), with the pool package copied in as `m31_pool` (its
`verifier_core` pointed at the work directory's identical vendored copy), writes the fixtures and
runs `snforge test --profile contract`. The test checks that the deployed pool's class hash is the
one `scarb build` produced in `bench/m31-pool/cairo`.

Secrets (keys, openings) stay in RUN; the fixtures carry public data only.
Usage: account_bound_e2e.py WORK RUN
"""
from pathlib import Path
import json, os, re, secrets, shutil, subprocess, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT = ROOT / 'bench/m31-private-wrapper/client-port'
WALLET = CLIENT / 'target/release/examples/wallet'
KAT = CLIENT / 'cairo-r5/kat/v5.cjs'
TEMPLATE = CLIENT / 'cairo-r5'
POOL_PKG = HERE / 'cairo'
TOOLS = '/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin'
sys.path.insert(0, str(HERE))
from gen_binding_v5_kat import delivery, ref  # noqa: E402

P = 2**31 - 1
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, TOKEN, ACCOUNT, RECIPIENT = 0x7e57b301, 0x7e57b3a1, 0x7e57b3c0, 0xb0b
E, Q, W, T = 1500, 100, 4096, 86400
SUBMIT = 5000
BASE = SUBMIT - 11
OS_PROGRAM = 0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1
VALID_UNTIL = (SUBMIT + E + Q - 1) // Q * Q
DEPOSITS = [1000, 500]
S1_WITHDRAWAL = 400


def wallet(*args):
    r = subprocess.run([str(WALLET), *map(str, args)], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def node(script, *args):
    r = subprocess.run(['node', '-e', script, *map(str, args)], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def digest():
    return [secrets.randbelow(P - 1) + 1 for _ in range(9)]


def ciphertext():
    return [secrets.randbelow(2**248) for _ in range(9)] + [secrets.randbelow(2**200)]


def note(sk, rho, amount, account):
    receiver = wallet('keys5', json.dumps(sk), hex(account))['receiver']
    inner = wallet('inner', json.dumps(receiver), json.dumps(rho))
    cm = wallet('commitment', hex(CHAIN), hex(POOL), hex(TOKEN), amount, json.dumps(inner))
    return inner, cm


def binding(pub):
    """`TMR0_BIND_V5` from public.json (validate_bridge_r5.binding)."""
    b = [int.from_bytes(b'TMR0_BIND_V5', 'big'), int(pub['chain'], 16), int(pub['pool'], 16), int(pub['token_out'], 16)]
    b += pub['root'] + pub['nullifiers'][0] + pub['nullifiers'][1]
    b += pub['commitments'][0] + [int(pub['deliveries'][0], 16)] + pub['commitments'][1] + [int(pub['deliveries'][1], 16)]
    b += [int(pub['withdrawal_recipient'], 16), int(pub['withdrawal_amount']), int(pub['intent'], 16)]
    b += pub['identity'] + [int(pub['valid_until'])]
    return ref.poseidon_hash_span(b)


def spend_felts(pub, cts):
    """The pool's V5 `Spend`, Serde-encoded, from the proof's public statement and the ciphertexts."""
    for j in range(2):
        assert delivery(cts[j]) == int(pub['deliveries'][j], 16), 'the pool derives each delivery from its ciphertext'
    f = [int(pub['chain'], 16), int(pub['pool'], 16), int(pub['token_out'], 16), 9, *pub['root'], 18,
         *pub['nullifiers'][0], *pub['nullifiers'][1], 2]
    for j in range(2):
        f += [9, *pub['commitments'][j], 10, *cts[j]]
    f += [int(pub['withdrawal_recipient'], 16), int(pub['withdrawal_amount']), int(pub['intent'], 16), 9, *pub['identity'],
          int(pub['valid_until']), binding(pub)]
    return f


def assemble(work):
    """The pool package and pool_e2e as members of the work directory's workspace."""
    pool = work / 'm31_pool'
    shutil.rmtree(pool, ignore_errors=True)
    pool.mkdir()
    shutil.copytree(POOL_PKG / 'src', pool / 'src')
    toml = (POOL_PKG / 'Scarb.toml').read_text()
    toml, n = re.subn(r'stwo_verifier_core = \{ path = "[^"]*" \}', 'stwo_verifier_core = { path = "../vendor/verifier_core" }', toml)
    assert n == 1
    # A lib target, so pool_e2e can depend on it and deploy its contracts.
    toml = toml.replace('[dependencies]', '[lib]\n\n[dependencies]', 1)
    (pool / 'Scarb.toml').write_text(toml)
    shutil.rmtree(work / 'pool_e2e', ignore_errors=True)
    shutil.copytree(TEMPLATE / 'pool_e2e', work / 'pool_e2e', ignore=shutil.ignore_patterns('target', 'fixtures'))
    shutil.copy(TEMPLATE / 'account_tests/Scarb.toml', work / 'account_tests/Scarb.toml')
    root = (work / 'Scarb.toml').read_text()
    for member in ('m31_pool', 'pool_e2e'):
        if f'"{member}"' not in root:
            root = root.replace('members = [\n', f'members = [\n    "{member}",\n', 1)
    (work / 'Scarb.toml').write_text(root)


def main():
    work, run = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    run.mkdir(parents=True, exist_ok=True)
    assert (work / 'build-record.json').exists(), 'WORK is a bridge built by build_bridge_arith.py'
    assemble(work)
    pool_class = node(
        "const {hash}=require(process.argv[1]);const s=JSON.parse(require('fs').readFileSync(process.argv[2]));"
        "console.log(JSON.stringify(hash.computeSierraContractClassHash(s)))",
        ROOT / 'sdk/ts/node_modules/starknet', POOL_PKG / 'target/dev/m31_pool_M31PoolV3.contract_class.json')
    # Private wallet state, kept in RUN so a rerun reuses its proofs.
    state = run / 'private-wallet.json'
    if state.exists():
        s = json.loads(state.read_text())
        deposits, leaves, cts, spends = s['deposits'], s['leaves'], s['ciphertexts'], s['spends']
    else:
        keys = {'bound': (digest(), digest()), 'ordinary': (digest(), digest())}
        deposits, leaves = [], []
        for (name, account), amount in zip([('bound', ACCOUNT), ('ordinary', 0)], DEPOSITS):
            sk, rho = keys[name]
            inner, cm = note(sk, rho, amount, account)
            deposits.append({'amount': amount, 'inner': inner, 'ciphertext': ciphertext()})
            leaves.append(cm)
        out = lambda amount, ct: {'receiver': digest(), 'rho': digest(), 'amount': str(amount), 'delivery': hex(delivery(ct))}
        cts = {'s1': [ciphertext(), ciphertext()], 's2': [ciphertext(), ciphertext()]}
        spends = {
            's1': {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': leaves,
                   'inputs': [{'sk': keys['bound'][0], 'rho': keys['bound'][1], 'amount': str(DEPOSITS[0]), 'position': 0}],
                   'outputs': [out(DEPOSITS[0] - S1_WITHDRAWAL, cts['s1'][0]), out(0, cts['s1'][1])],
                   'withdrawal': {'recipient': hex(RECIPIENT), 'amount': str(S1_WITHDRAWAL)},
                   'account': hex(ACCOUNT), 'valid_until': VALID_UNTIL},
            's2': {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': leaves,
                   'inputs': [{'sk': keys['ordinary'][0], 'rho': keys['ordinary'][1], 'amount': str(DEPOSITS[1]), 'position': 1}],
                   'outputs': [out(300, cts['s2'][0]), out(200, cts['s2'][1])],
                   'withdrawal': {'recipient': '0x0', 'amount': '0'},
                   'account': '0x0', 'valid_until': VALID_UNTIL},
        }
        state.write_text(json.dumps({'keys': keys, 'deposits': deposits, 'leaves': leaves, 'ciphertexts': cts, 'spends': spends}))
        os.chmod(state, 0o600)
    root = wallet('root', json.dumps(leaves))
    fixtures = work / 'pool_e2e/fixtures'
    fixtures.mkdir(parents=True, exist_ok=True)
    summary = {'pool_class': pool_class, 'valid_until': VALID_UNTIL, 'proofs': {}}
    publics = {}
    for name, sp in spends.items():
        (run / f'{name}.json').write_text(json.dumps(sp))
        d = run / name
        if not (d / 'public.json').exists():
            r = subprocess.run([str(WALLET), 'prove5', str(run / f'{name}.json'), str(d)], capture_output=True, text=True)
            assert r.returncode == 0, r.stderr[-3000:]
        pub = json.loads((d / 'public.json').read_text())
        assert pub['root'] == root and int(pub['valid_until']) == VALID_UNTIL
        publics[name] = pub
        report = json.loads((d / 'report.json').read_text())
        summary['proofs'][name] = {k: report[k] for k in ('trace_log_size', 'proof_felts')}
        summary['proofs'][name]['binding'] = hex(binding(pub))
        felts = json.loads((d / 'cairo-arguments.json').read_text())
        assert int(felts[0], 16) == len(felts) - 1
        (fixtures / f'{name}-proof.txt').write_text('\n'.join(str(int(x, 16)) for x in felts[1:]) + '\n')
        (fixtures / f'{name}-spend.txt').write_text('\n'.join(map(str, spend_felts(pub, cts[name]))) + '\n')
    # S1's spend message and binding from starknet.js (independent of the Cairo code).
    salt = secrets.randbelow(2**251 - 1) + 1
    signature = [secrets.randbelow(2**251), secrets.randbelow(2**251)]
    ref_s1 = node(
        "const v=require(process.argv[1]);const p=v.readPublic(process.argv[2]);"
        "console.log(JSON.stringify({hash:v.hex(v.messageHash(p,BigInt(process.argv[3]))),binding:v.hex(v.binding(p)),sig:v.hex(v.poseidon(JSON.parse(process.argv[4])))}))",
        KAT, run / 's1', salt, json.dumps([str(s) for s in signature]))
    for name in spends:
        b = node("const v=require(process.argv[1]);console.log(JSON.stringify(v.hex(v.binding(v.readPublic(process.argv[2])))))", KAT, run / name)
        assert int(b, 16) == binding(publics[name]), f'{name}: starknet.js and Python bindings agree'
    constants = [CHAIN, POOL, TOKEN, ACCOUNT, RECIPIENT, E, Q, W, T, SUBMIT, BASE, OS_PROGRAM, int(pool_class, 16), *root,
                 salt, int(ref_s1['hash'], 16), int(ref_s1['sig'], 16), S1_WITHDRAWAL, *signature]
    (fixtures / 'constants.txt').write_text('\n'.join(map(str, constants)) + '\n')
    (fixtures / 'deposits.txt').write_text(
        '\n'.join(str(x) for dep in deposits for x in [dep['amount'], *dep['inner'], *dep['ciphertext']]) + '\n')
    env = dict(os.environ, PATH=TOOLS + ':' + os.environ['PATH'])
    r = subprocess.run(['snforge', 'test', '--profile', 'contract'], cwd=work / 'pool_e2e', capture_output=True, text=True, env=env)
    (run / 'snforge.log').write_text(r.stdout + r.stderr)
    lines = (r.stdout + r.stderr).splitlines()
    summary['tests'] = [l for l in lines if l.startswith(('[PASS]', '[FAIL]'))]
    summary['gas'] = [l.strip() for l in lines if l.strip().startswith('GAS ')]
    summary['result'] = next((l for l in lines if l.startswith('Tests:')), None)
    (run / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    assert r.returncode == 0, 'snforge failed; see RUN/snforge.log'


if __name__ == '__main__':
    main()
