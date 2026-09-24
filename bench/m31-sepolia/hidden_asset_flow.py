"""Hidden-asset spends and ERC721/ERC1155 notes on Sepolia (`docs/hidden-asset-spec.md`):
M31 pool V2 with R0 V4 and P1 statement accounts, wrapped as large proofs.

  deploy    declare and deploy pool V2, the R4 and P1 statement accounts and adapters, the
            reference escrow, a test ERC721 and ERC1155 and an account-like ERC1155 recipient
  deposits  (on chain) Alice's 1000 of token A (ERC20 pull); Alice's NFT #2 (ERC721 push, hook);
            an ERC1155 escrow policy note of 300 x id 7 (ERC1155 push, hook), arbiter = relayer
  S1  R0 V4: Alice pays Bob 600 of 1000 A (one input + dummy); asset hidden
  S2  R0 V4: Alice gives Bob NFT #2 (one input + dummy, one output + dummy); asset hidden
  S3  P1: the relayer, as arbiter, approves the release on chain; the executor settles it,
      paying 300 units by ERC1155 safe transfer to the account-like recipient
  S4  R0 V4: Alice withdraws NFT #2 (two dummy outputs); asset published

Each spend is proved from the pool's events, executed in the virtual OS on live Sepolia state,
wrapped as a large proof and submitted to the gateway; while the gateway rejects large proofs,
the exact signed transaction is simulated with validation against live state. S2 and S4 each
spend NFT #2 from the deposit state and are simulated independently. Checkpointed in the private
runtime (`TEMPLAR_SEPOLIA_RUN`)."""
from sepolia import *
import hashlib, shutil, sys
import proof2, wallet
sys.path.insert(0, str(ROOT / 'bench/m31-pool'))
import hidden_asset as ha  # noqa: E402
import policy_note as pn  # noqa: E402
import policy_wallet as pw  # noqa: E402

POOL_CRATE = ROOT / 'bench/m31-pool/cairo'
OS_PROGRAM = 0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1
MAX_PROOF_AGE = 4096
TOKEN_A = int(load(ROOT / 'bench/return-note-e2e/results/public/deployment.json')['token_a'], 16)
NFT_ID, MULTI_ID, ERC20_AMOUNT, MULTI_AMOUNT, DEADLINE_BLOCKS = 2, 7, 1000, 300, 50_000
PROOF_TX_L2 = 600_000_000
BUILDS = {'statement4': ('bridge-r4', 'TMPZR0_PAYMENT_V4'), 'statement1': ('bridge-p1', 'TMPZP1_POLICY_V1')}
ACCOUNT_CLASS = {'statement4': 'PaymentVerifierAccount', 'statement1': 'PolicyVerifierAccount'}
assert int(rpc('starknet_chainId', []), 16) == CHAIN
RUN.mkdir(parents=True, exist_ok=True)
os.chmod(RUN, 0o700)
manifest = load(RUN / 'manifest.json')
if manifest is None:
    manifest = {'salt_base': hex(int.from_bytes(os.urandom(31), 'big'))}
    save(RUN / 'manifest.json', manifest)
progress = load(RUN / 'private-progress.json', {'stage': 0})


def checkpoint(stage=None):
    if stage is not None:
        progress['stage'] = stage
    save(RUN / 'private-progress.json', progress)


# ---------------------------------------------------------------- declare builds of the accounts

def declare_build(key):
    """A gas-enabled copy of a statement-account build whose CASM must equal the audited build."""
    build, tag = BUILDS[key]
    src, dst = ROOT / 'target' / build, ROOT / 'target' / (build + '-declare')
    record = load(src / 'build-record.json')
    assert record['message_tag'] == tag
    if not dst.exists():
        dst.mkdir()
        for part in ['Scarb.toml', 'Scarb.lock', 'bridge', 'account', 'vendor']:
            if (src / part).exists():
                (shutil.copytree if (src / part).is_dir() else shutil.copy2)(src / part, dst / part)
        toml = (dst / 'Scarb.toml').read_text()
        assert '[cairo]\nenable-gas = false\n' in toml
        (dst / 'Scarb.toml').write_text(toml.replace('[cairo]\nenable-gas = false\n', '[cairo]\n'))
    subprocess.run([SCARB, '--release', 'build', '-p', 'templar_membership_account'], cwd=dst, env=ENV, check=True, capture_output=True)
    artifact = f'templar_membership_account_{ACCOUNT_CLASS[key]}.compiled_contract_class.json'
    casm = load(dst / 'target/release' / artifact)['bytecode']
    assert casm == load(src / 'target/contract' / artifact)['bytecode'], f'{key}: declare build differs from the audited build'
    assert len(casm) <= 81_920
    return dst, record


def class_hash(crate, package, contract):
    args = [SNCAST, '--json', 'utils', 'class-hash', '--contract-name', contract] + (['--package', package] if package else [])
    return json.loads(subprocess.check_output(args, cwd=crate, env=ENV, text=True).strip().splitlines()[-1])['class_hash']


def deploy(name, class_key, data, classes):
    salt = (int(manifest['salt_base'], 16) + int.from_bytes(('M31_V2_' + name).encode(), 'big')) % 2**251
    v = normal_tx('deploy-' + name, ['deploy', '--class-hash', classes[class_key], '--salt', hex(salt),
                                     *(['--constructor-calldata', *[h(x) for x in data]] if data else []), *bounds(80_000_000)], HERE)
    return v['contract_address']


if progress['stage'] == 0:
    builds = {k: declare_build(k) for k in BUILDS}
    # (name, crate, package, contract, declaration L2 gas bound, fee ceiling)
    CLASSES = [
        ('pool', POOL_CRATE, None, 'M31PoolV2', 5_300_000_000, 230 * 10**18),
        ('adapter', POOL_CRATE, None, 'Proof2Adapter', 250_000_000, MAX_DECLARE_FEE_FRI),
        ('escrow', POOL_CRATE, None, 'PolicyEscrow', 800_000_000, MAX_DECLARE_FEE_FRI),
        ('erc721', POOL_CRATE, None, 'TestERC721', 1_500_000_000, MAX_DECLARE_FEE_FRI),
        ('erc1155', POOL_CRATE, None, 'TestERC1155', 1_500_000_000, MAX_DECLARE_FEE_FRI),
        ('account_like', POOL_CRATE, None, 'AccountLikeRecipient', 400_000_000, MAX_DECLARE_FEE_FRI),
        ('statement4', builds['statement4'][0], 'templar_membership_account', 'PaymentVerifierAccount', 4_600_000_000, MAX_DECLARE_FEE_FRI),
        ('statement1', builds['statement1'][0], 'templar_membership_account', 'PolicyVerifierAccount', 4_600_000_000, MAX_DECLARE_FEE_FRI),
    ]
    classes = load(RUN / 'classes.json', {})
    for name, crate, package, contract, gas, ceiling in CLASSES:
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
                                              *bounds(gas, ceiling)], crate, url=DECLARE_RPC)
            assert int(v['class_hash'], 16) == int(expected, 16)
            classes[name] = v['class_hash']
        save(RUN / 'classes.json', classes)
    d = load(RUN / 'deployment.json', {})
    if 'pool' not in d:
        # The constructor needs a nonzero verifier; the relayer stands in until the R4 adapter exists.
        d['pool'] = deploy('pool', 'pool', [ACCOUNT, ACCOUNT, 1, 0], classes)
        save(RUN / 'deployment.json', d)
    for key, (_, tag) in BUILDS.items():
        if key not in d:
            d[key] = deploy(key, key, [], classes)
            d['adapter_' + key] = deploy('adapter-' + key, 'adapter', [d['pool'], d[key], classes[key], OS_PROGRAM, MAX_PROOF_AGE,
                                                                       hex(int.from_bytes(tag.encode(), 'big'))], classes)
            save(RUN / 'deployment.json', d)
    for name, key, data in [('escrow', 'escrow', [d['pool']]), ('erc721', 'erc721', []), ('erc1155', 'erc1155', []),
                            ('account_like', 'account_like', [])]:
        if name not in d:
            d[name] = deploy(name, key, data, classes)
            save(RUN / 'deployment.json', d)
    d.update(classes=classes, token=hex(TOKEN_A), os_program=hex(OS_PROGRAM), max_proof_age=MAX_PROOF_AGE,
             start_block=load(RUN / 'steps/deploy-pool/receipt.json')['block_number'],
             builds={k: {'circuit_hash_u32_le': r['circuit_hash_u32_le'], 'trusted_manifest_sha256': r['trusted_manifest_sha256']}
                     for k, (_, r) in builds.items()})
    save(RUN / 'deployment.json', d)
    invoke('set-verifier', d['pool'], 'set_verifier', [d['adapter_statement4']], 20_000_000, HERE)
    invoke('set-policy-verifier', d['pool'], 'set_policy_verifier', [d['adapter_statement1']], 20_000_000, HERE)
    invoke('approve', TOKEN_A, 'approve', [d['pool'], ERC20_AMOUNT, 0], 20_000_000, HERE)
    assert call(d['pool'], 'get_verifier') == [int(d['adapter_statement4'], 16)]
    assert call(d['pool'], 'get_leaf_count') == [0]
    save(RUN / 'source-snapshot.json', {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in sorted((POOL_CRATE / 'src').rglob('*.cairo'))})
    checkpoint(1)

D = load(RUN / 'deployment.json')
POOL = int(D['pool'], 16)
NFT, MULTI, ESCROW, RECIPIENT = (int(D[k], 16) for k in ('erc721', 'erc1155', 'escrow', 'account_like'))
NFT_ASSET, MULTI_ASSET = ha.asset_id(ha.ERC721, NFT, NFT_ID), ha.asset_id(ha.ERC1155, MULTI, MULTI_ID)
seeds = load(RUN / 'private-seeds.json')
if seeds is None:
    seeds = {k: os.urandom(32).hex() for k in ('alice', 'bob', 'depositor')}
    save(RUN / 'private-seeds.json', seeds)
    os.chmod(RUN / 'private-seeds.json', 0o600)
alice, bob, dep = (pw.Wallet(bytes.fromhex(seeds[k])) for k in ('alice', 'bob', 'depositor'))


def events(name):
    key = selector(name)
    out, token = [], None
    while True:
        f = {'from_block': {'block_number': D['start_block']}, 'to_block': 'latest', 'address': D['pool'], 'keys': [[key]], 'chunk_size': 200}
        if token:
            f['continuation_token'] = token
        r = rpc('starknet_getEvents', [f])
        out += r['events']
        token = r.get('continuation_token')
        if not token:
            break
    return [[int(x, 16) for x in e['data']] for e in out]


def published():
    """`(index, commitment, ciphertext words)` for every leaf, from `NotePublished`."""
    notes = {}
    for data in events('NotePublished'):
        index, n_cm = data[0], data[1]
        cm = data[2:2 + n_cm]
        rest = data[2 + n_cm + 1:]
        notes[index] = (cm, rest[1:1 + rest[0]])
    assert sorted(notes) == list(range(len(notes))) and len(notes) == call(POOL, 'get_leaf_count')[0]
    return [(i, notes[i][0], notes[i][1]) for i in range(len(notes))]


if progress['stage'] == 1:
    notes = progress.setdefault('notes', {})
    if 'a1000' not in notes:
        rho = pn.random_digest()
        notes['a1000'] = {'rho': rho, 'inner': wallet.inner(alice.receiver(0), rho),
                          'ct': pw.to_words(pw.seal(alice.incoming(0).public_key, pw.m301(TOKEN_A, alice.receiver(0), rho, ERC20_AMOUNT)))}
        rho = pn.random_digest()
        notes['nft'] = {'rho': rho, 'inner': wallet.inner(alice.receiver(1), rho),
                        'ct': pw.to_words(pw.seal(alice.incoming(1).public_key, pw.m301(NFT_ASSET, alice.receiver(1), rho, 1)))}
        deadline = rpc('starknet_blockNumber', []) + DEADLINE_BLOCKS
        release = pn.fixed([], withdrawal=(RECIPIENT, MULTI_AMOUNT))
        e = pw.new_policy_note(dep, CHAIN, POOL, MULTI_ASSET, MULTI_AMOUNT, ESCROW, int(D['classes']['escrow'], 16), int(ACCOUNT, 16),
                               deadline, [release])
        notes['escrow'] = {**e, 'inner': wallet.inner(e['info']['receiver'], e['rho']), 'deadline': deadline}
        checkpoint()
    n = notes['a1000']
    invoke('deposit-erc20', POOL, 'deposit', [TOKEN_A, ERC20_AMOUNT, 9, *n['inner'], 10, *n['ct']], 150_000_000, HERE)
    invoke('mint-nft', NFT, 'mint', [ACCOUNT, NFT_ID, 0, 1, 0], 30_000_000, HERE)
    n = notes['nft']
    invoke('deposit-nft', NFT, 'safe_transfer_from', [ACCOUNT, POOL, NFT_ID, 0, 19, *ha.hook_data(n['inner'], n['ct'])], 200_000_000, HERE)
    invoke('mint-multi', MULTI, 'mint', [ACCOUNT, MULTI_ID, 0, MULTI_AMOUNT, 0], 30_000_000, HERE)
    n = notes['escrow']
    invoke('deposit-multi', MULTI, 'safe_transfer_from',
           [ACCOUNT, POOL, MULTI_ID, 0, MULTI_AMOUNT, 0, 19, *ha.hook_data(n['inner'], n['creation_ciphertext'])], 200_000_000, HERE)
    leaves = [cm for _, cm, _ in published()]
    assert leaves == [wallet.commitment(CHAIN, POOL, TOKEN_A, ERC20_AMOUNT, notes['a1000']['inner']),
                      wallet.commitment(CHAIN, POOL, NFT_ASSET, 1, notes['nft']['inner']),
                      wallet.commitment(CHAIN, POOL, MULTI_ASSET, MULTI_AMOUNT, notes['escrow']['inner'])], 'on-chain leaves differ from the wallets'
    # The NFT registrations ran `get_class_hash_at_syscall` on the undeployed identifiers (HA-IC6).
    assert call(POOL, 'get_asset', [NFT_ASSET])[0] == ha.ERC721 and call(POOL, 'get_asset', [MULTI_ASSET])[0] == ha.ERC1155
    assert call(POOL, 'get_held', [NFT_ASSET])[:2] == [1, 0] and call(POOL, 'get_held', [MULTI_ASSET])[:2] == [MULTI_AMOUNT, 0]
    checkpoint(2)


def case(name, kind, build):
    """Prove (wallet) and serve (OS on live state, large proof) one spend; checkpointed."""
    folder = RUN / 'cases' / name
    c = load(folder / 'case.json')
    if c is None:
        public, calldata, client = build(folder)
        if kind == 'R4':
            bind, statement, klass, tag = ha.binding(public), D['statement4'], D['classes']['statement4'], 'TMPZR0_PAYMENT_V4'
        else:
            bind, statement, klass, tag = pn.binding(public), D['statement1'], D['classes']['statement1'], 'TMPZP1_POLICY_V1'
        server = proof2.serve(folder / 'client', folder / 'server', D, statement, klass, int.from_bytes(tag.encode(), 'big'), bind)
        c = {'kind': kind, 'calldata': calldata, 'client': client, 'server': server, 'token_out': public.get('token_out')}
        save(folder / 'case.json', c)
    return c


def submit(name, fn, c):
    """Post to the gateway; on rejection simulate the exact signed transaction at the latest block."""
    folder = RUN / 'cases' / name
    try:
        proof_invoke(name, POOL, fn, c['calldata'], folder / 'server', PROOF_TX_L2, HERE)
        return {'included': True}
    except RuntimeError as e:
        out = {'included': False, 'gateway': load(RUN / 'steps' / name / 'gateway-response.json'), 'error': str(e)[:300]}
    tx = load(RUN / 'steps' / name / 'signed-request.json')['params']['invoke_transaction']
    sim = rpc('starknet_simulateTransactions', ['latest', [tx], []], timeout=300)[0]
    save(RUN / 'results' / f'{name}-simulation.json', sim)
    tr = sim['transaction_trace']
    ex = tr['execute_invocation']
    assert 'revert_reason' not in ex, f'{name}: ' + ex['revert_reason'][:1500]
    out['simulation'] = {'result': 'SUCCEEDED (with validation, latest block)', 'total_l2_gas': tr['execution_resources']['l2_gas'],
                         'l1_data_gas': tr['execution_resources']['l1_data_gas'], 'pool_call_l2_gas': ex['calls'][0]['execution_resources']['l2_gas'],
                         'fee_STRK': int(sim['fee_estimation']['overall_fee'], 16) / 1e18}
    return out


def v4(name, outputs, withdrawal, asset, position, sk, rho, amount):
    def build(folder):
        leaves = [cm for _, cm, _ in published()]
        body = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(asset), 'leaves': leaves,
                'inputs': [{'sk': sk, 'rho': rho, 'amount': str(amount), 'position': position}],
                'outputs': [o for o, _ in outputs], 'withdrawal': withdrawal}
        client = ha.prove4(body, folder / 'client')
        public = load(folder / 'client/public.json')
        return public, ha.encode_spend(public, [ct for _, ct in outputs]) + [0], client
    return case(name, 'R4', build)


if progress['stage'] == 2:
    notes = progress['notes']
    outcomes = progress.setdefault('outcomes', {})
    no_w = {'recipient': '0x0', 'amount': '0'}
    # S1: 600 of A to Bob, 400 change; the asset stays hidden.
    if 's1' not in outcomes:
        pay, change = ha.output_to(bob, 0, TOKEN_A, 600), ha.output_to(alice, 2, TOKEN_A, 400)
        c = v4('s1', [pay, change], no_w, TOKEN_A, 0, alice.sk(0), notes['a1000']['rho'], ERC20_AMOUNT)
        assert c['token_out'] == '0x0'
        outcomes['s1'] = submit('s1', 'apply_spend', c)
        checkpoint()
    # S2: NFT #2 to Bob; hidden.
    if 's2' not in outcomes:
        gift = ha.output_to(bob, 1, NFT_ASSET, 1)
        c = v4('s2', [gift, ha.dummy_output()], no_w, NFT_ASSET, 1, alice.sk(1), notes['nft']['rho'], 1)
        assert c['token_out'] == '0x0'
        outcomes['s2'] = submit('s2', 'apply_spend', c)
        checkpoint()
    # S3: the arbiter (the relayer) approves on chain; then the release is proved and simulated.
    if 's3' not in outcomes:
        e = notes['escrow']
        def build3(folder):
            leaves = [cm for _, cm, _ in published()]
            spend = pn.spend_request(CHAIN, POOL, MULTI_ASSET, leaves, e['cap'], e['rho'], MULTI_AMOUNT, 2, e['policy'], 1, 0, pn.data_felt([]))
            (folder / 'client').mkdir(parents=True, exist_ok=True)
            (folder / 'client/spend.json').write_text(json.dumps(spend))
            r = subprocess.run(['taskset', '-c', '0-3', str(pn.WALLET), 'prove-policy', str(folder / 'client/spend.json'),
                                str(folder / 'client'), '16'], capture_output=True, text=True, env=dict(os.environ, RAYON_NUM_THREADS='4'))
            assert r.returncode == 0, r.stderr[-2000:]
            public = load(folder / 'client/public.json')
            rep = load(folder / 'client/report.json')
            calldata = pn.encode_spend(public, pn.binding(public)) + [0, 2, 0, 0, 0]
            return public, calldata, {k: rep[k] for k in ('trace_log_size', 'proving_seconds', 'proof_felts')}
        c = case('s3', 'P1', build3)
        policy_id = pn.ref.poseidon_hash_span(load(RUN / 'cases/s3/client/public.json')['policy_id'])
        invoke('approve-release', ESCROW, 'approve', [policy_id, 1], 30_000_000, HERE)
        outcomes['s3'] = submit('s3', 'apply_policy_spend', c)
        checkpoint()
    # S4: Alice withdraws NFT #2; two dummy outputs; the asset is published.
    if 's4' not in outcomes:
        c = v4('s4', [ha.dummy_output(), ha.dummy_output()], {'recipient': hex(0xb0b), 'amount': '1'}, NFT_ASSET, 1,
               alice.sk(1), notes['nft']['rho'], 1)
        assert int(c['token_out'], 16) == NFT_ASSET
        outcomes['s4'] = submit('s4', 'apply_spend', c)
        checkpoint()
    summary = {'deployment': {k: v for k, v in D.items()}, 'outcomes': outcomes,
               'cases': {n: {k: load(RUN / 'cases' / n / 'case.json')[k] for k in ('kind', 'client', 'token_out')} |
                         {'server': {k: load(RUN / 'cases' / n / 'case.json')['server'][k]
                                     for k in ('base_block', 'capture_seconds', 'proof2_wall_seconds', 'proof_bytes', 'proof2_max_rss_gib')}}
                         for n in ('s1', 's2', 's3', 's4')}}
    save(RUN / 'results/summary.json', summary)
    print(json.dumps(summary['outcomes'], indent=1)[:4000], flush=True)
    checkpoint(3)
