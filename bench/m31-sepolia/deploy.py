"""Declare and deploy the option-A Sepolia run: synthetic token, R0 statement account (the
`bridge-r0w` build: R0 V2, single-permutation nodes), M31 pool (frontier storage) and PROOF2
adapter; then attach the adapter and approve the pool. Checkpointed; bounded fees."""
from sepolia import *
import hashlib, shutil, sys

STATEMENT_BUILD = ROOT / 'target/bridge-r0w'
# sncast builds with the release profile, but the bridge workspace disables gas at its root (for
# the standalone executable). The declaration builds a copy with gas enabled; its CASM must equal
# the audited `contract`-profile build.
DECLARE_BUILD = ROOT / 'target/bridge-r0w-declare'
POOL_CRATE = ROOT / 'bench/m31-pool/cairo'
OS_PROGRAM = 0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1
MAX_PROOF_AGE = 4096
SUPPLY = 10_000

assert int(rpc('starknet_chainId', []), 16) == CHAIN
manifest = load(RUN / 'manifest.json')
record = load(STATEMENT_BUILD / 'build-record.json')
assert record['message_tag'] == 'TMPZR0_PAYMENT_V2' and record['n_outputs'] == 28

if not DECLARE_BUILD.exists():
    DECLARE_BUILD.mkdir()
    for part in ['Scarb.toml', 'Scarb.lock', 'bridge', 'account', 'vendor']:
        (shutil.copytree if (STATEMENT_BUILD / part).is_dir() else shutil.copy2)(STATEMENT_BUILD / part, DECLARE_BUILD / part)
    toml = (DECLARE_BUILD / 'Scarb.toml').read_text()
    assert '[cairo]\nenable-gas = false\n' in toml
    (DECLARE_BUILD / 'Scarb.toml').write_text(toml.replace('[cairo]\nenable-gas = false\n', '[cairo]\n'))
subprocess.run([SCARB, '--release', 'build', '-p', 'templar_membership_account'], cwd=DECLARE_BUILD, env=ENV, check=True, capture_output=True)
artifact = 'templar_membership_account_PaymentVerifierAccount.compiled_contract_class.json'
declared_casm = load(DECLARE_BUILD / 'target/release' / artifact)['bytecode']
assert declared_casm == load(STATEMENT_BUILD / 'target/contract' / artifact)['bytecode'], 'declare build differs from the audited build'
assert len(declared_casm) <= 81_920

# (name, crate, package, contract, L2 gas bound for the declaration: the public endpoint's
# estimate, about 1.1x; 2026-09-23 estimates 228M, 3,474M, 145M, 3,686M)
CLASSES = [
    ('token', POOL_CRATE, None, 'E2EToken', 250_000_000),
    ('pool', POOL_CRATE, None, 'M31Pool', 3_850_000_000),
    ('adapter', POOL_CRATE, None, 'Proof2Adapter', 160_000_000),
    ('statement', DECLARE_BUILD, 'templar_membership_account', 'PaymentVerifierAccount', 4_100_000_000),
]


def class_hash(crate, package, contract):
    args = [SNCAST, '--json', 'utils', 'class-hash', '--contract-name', contract] + (['--package', package] if package else [])
    out = subprocess.check_output(args, cwd=crate, env=ENV, text=True)
    return json.loads(out.strip().splitlines()[-1])['class_hash']


if '--check' in sys.argv:
    # Read-only: class hashes, declaration status and fee estimates; nothing is sent.
    for name, crate, package, contract, gas in CLASSES:
        expected = class_hash(crate, package, contract)
        try:
            rpc('starknet_getClass', ['latest', expected])
            print(json.dumps({'class': name, 'class_hash': expected, 'declared': True}))
            continue
        except RuntimeError as e:
            assert 'not found' in str(e).lower()
        out = subprocess.run([SNCAST, '--account', ACCOUNT_NAME, '--accounts-file', ACCOUNTS_FILE, '--json', 'declare', '--url', DECLARE_RPC,
                              '--contract-name', contract, *(['--package', package] if package else []), '--dry-run'],
                             cwd=crate, env=ENV, capture_output=True, text=True)
        est = [json.loads(l) for l in out.stdout.splitlines() if l.startswith('{') and '"command"' in l]
        print(json.dumps({'class': name, 'class_hash': expected, 'declared': False, 'estimate': est[-1] if est else out.stderr[-600:]}))
    sys.exit(0)

classes = load(RUN / 'classes.json', {})
for name, crate, package, contract, gas in CLASSES:
    if name in classes:
        continue
    expected = class_hash(crate, package, contract)
    try:
        rpc('starknet_getClass', ['latest', expected])
        classes[name] = expected
    except RuntimeError as e:
        if 'not found' not in str(e).lower():
            raise
        print('declare', contract, expected, flush=True)
        v = normal_tx('declare-' + name, ['declare', '--contract-name', contract, *(['--package', package] if package else []),
                                          *bounds(gas, MAX_DECLARE_FEE_FRI)], crate, url=DECLARE_RPC)
        assert int(v['class_hash'], 16) == int(expected, 16)
        classes[name] = v['class_hash']
    save(RUN / 'classes.json', classes)


def deploy(name, data):
    salt = (int(manifest['salt_base'], 16) + int.from_bytes(('M31_SEPOLIA_' + name).encode(), 'big')) % 2**251
    v = normal_tx('deploy-' + name, ['deploy', '--class-hash', classes[name], '--salt', hex(salt),
                                     '--constructor-calldata', *[h(x) for x in data], *bounds(60_000_000)], HERE)
    return v['contract_address']


d = load(RUN / 'deployment.json', {})
if 'adapter' not in d:
    d['token'] = deploy('token', [ACCOUNT, SUPPLY, 0])
    # Owner, verifier (attached below), format 1 (single-permutation nodes), frontier storage.
    d['pool'] = deploy('pool', [ACCOUNT, 0, 1, 0])
    d['statement'] = deploy('statement', [])
    d['adapter'] = deploy('adapter', [d['pool'], d['statement'], classes['statement'], OS_PROGRAM, MAX_PROOF_AGE])
    d.update(classes=classes, os_program=hex(OS_PROGRAM), max_proof_age=MAX_PROOF_AGE, supply=SUPPLY,
             start_block=load(RUN / 'steps/deploy-token/receipt.json')['block_number'],
             statement_build={'circuit_hash_u32_le': record['circuit_hash_u32_le'],
                              'trusted_manifest_sha256': record['trusted_manifest_sha256'], 'fork_commit': record['fork_commit']})
    save(RUN / 'deployment.json', d)
invoke('set-verifier', d['pool'], 'set_verifier', [d['adapter']], 20_000_000, HERE)
invoke('approve', d['token'], 'approve', [d['pool'], SUPPLY, 0], 20_000_000, HERE)
assert call(d['pool'], 'get_verifier') == [int(d['adapter'], 16)]
assert call(d['pool'], 'get_leaf_count') == [0]
save(RUN / 'source-snapshot.json', {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in [*sorted((POOL_CRATE / 'src').rglob('*.cairo')), *sorted((STATEMENT_BUILD / 'account/src').rglob('*.cairo')),
                                              *sorted((STATEMENT_BUILD / 'bridge/src').rglob('*.cairo'))]})
print('deployment ready', json.dumps(d), flush=True)
