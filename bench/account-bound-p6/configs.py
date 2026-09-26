#!/usr/bin/env python3
"""P6 end to end: the prover server's and the relayer's configuration for pool V3 on Sepolia.

Writes, in the run directory:
- `prover-v3.toml`: pool V3, relations r5 (the P5 statement account) and p1, bound spends for the
  launch classes (Argent 0.5.0, Braavos 1.2.0) on the local node, the P5 caps, the relayer's
  handoff, no payment (Sepolia is free);
- `relay.token`: the handoff's bearer token;
- `relayer-config.json`: the relayer (server/relayer) with the fresh account of relayer_account.py.

Nothing is sent. Usage: configs.py
"""
import hashlib
import json
import os
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_P6_RUN', Path.home() / '.local/share/templar/runs/account-bound-p6'))
RUN = RUNTIME / 'sepolia'
D = json.loads((RUN / 'deployment.json').read_text())
RELAYER = json.loads((RUN / 'relayer.json').read_text()) if (RUN / 'relayer.json').exists() else None
R5_BRIDGE = Path.home() / '.local/share/templar/runs/r5-p3b/bridge'
P1_BRIDGE = ROOT / 'target/bridge-p1'
LOCAL_RPC = 'http://127.0.0.1:9545/rpc/v0_10'
ARGENT_050 = '0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2'
BRAAVOS_120 = '0x03957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a'
CONFIG_HASH = '0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57'  # the pinned virtual OS (SDK SEPOLIA pins)
R5_CIRCUIT = [1903585510, 1708577544, 3915427995, 3101166941, 461832048, 2805149134, 1077751030, 1205594117]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def relation(name, statement, statement_class, tag, adapter, bridge):
    return f'''[[relation]]
name = "{name}"
statement_account = "{statement}"
statement_class = "{statement_class}"
account_tag = "{tag}"
adapter = "{adapter}"
bridge_dir = "{bridge}"
bridge_record_sha256 = "{sha(bridge / 'build-record.json')}"
bridge_executable_sha256 = "{sha(bridge / 'target/dev/templar_membership_bridge.executable.json')}"
'''


record = json.loads((R5_BRIDGE / 'build-record.json').read_text())
assert record['message_tag'] == 'TMPZR0_PAYMENT_V5' and record['circuit_hash_u32_le'] == R5_CIRCUIT
token = RUNTIME / 'relay.token'
if not token.exists():
    token.write_text(secrets.token_hex(24))
    token.chmod(0o600)
bound_dir = Path(f'/run/user/{os.getuid()}/templar-bound-p6')
bound_dir.mkdir(mode=0o700, exist_ok=True)

toml = f'''# Templar prover server: Sepolia, M31 pool V3 (P6, {D["start_block"]}). Written by bench/account-bound-p6/configs.py.
[server]
listen = "127.0.0.1:8490"
data_dir = "{RUNTIME / 'prover/jobs'}"
retention_secs = 7200
max_concurrent_jobs = 1
queue_capacity = 8
blocks_per_job = 60
relay_margin_blocks = 60
bound_retention_secs = 7200
bound_data_dir = "{bound_dir}"

[limits]
submissions_per_hour = 30
queued_per_address = 4

[network]
name = "sepolia"
chain_id = "SN_SEPOLIA"
rpc_url = "{LOCAL_RPC}"
pool = "{D['pool']}"
pool_version = 3
os_program = "{D['r0']['os_program']}"
max_proof_age = {D['r0']['max_proof_age']}
operator_node = true
bound_account_classes = ["{ARGENT_050}", "{BRAAVOS_120}"]

{relation('r5', D['r0']['statement'], D['r0']['statement_class'], 'TMPZR0_PAYMENT_V5', D['r0_adapter'], R5_BRIDGE)}
{relation('p1', D['p1']['statement'], D['p1']['statement_class'], 'TMPZP1_POLICY_V1', D['p1_adapter'], P1_BRIDGE)}
[binaries]
os_runner = "{ROOT / 'server/os-runner/target/release/templar-os-runner'}"
prove = "{ROOT / 'server/prove/target/release/templar-prove'}"
scarb = "/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb"

[sandbox]
cgroup_root = "self"
job_memory = "34G"
check_memory = "4G"

[caps]
os_steps = 4000000
builtins = {{ range_check_builtin = 450000, poseidon_builtin = 20000, pedersen_builtin = 150, ec_op_builtin = 5, output_builtin = 8 }}

[relay]
listen = "127.0.0.1:8491"
token_file = "{token}"

[prover]
cairo_fri_columns = 16
circuit_fri_columns = 16
stream_commitments = false
threads = 16
'''
(RUNTIME / 'prover/jobs').mkdir(parents=True, exist_ok=True)
(RUNTIME / 'prover-v3.toml').write_text(toml)

pool_pins = {
    'pool': D['pool'], 'deploymentBlock': D['start_block'], 'version': 'v5',
    'parameters': {'expiryWindow': D['parameters']['E_blocks'], 'quantum': D['parameters']['Q_blocks'],
                   'rootWindow': D['parameters']['W_blocks'], 'timelock': D['parameters']['T_seconds']},
    'adapter': D['r0_adapter'], 'adapterClass': D['adapter_class'], 'statement': D['r0']['statement'],
    'statementClass': D['r0']['statement_class'], 'accountTag': 'TMPZR0_PAYMENT_V5', 'osProgram': D['r0']['os_program'],
    'configHash': CONFIG_HASH, 'maxProofAge': D['r0']['max_proof_age'], 'circuitHash': R5_CIRCUIT,
}
if RELAYER:
    relayer = {
        'chainId': '0x534e5f5345504f4c4941', 'nodeUrl': LOCAL_RPC,
        'account': {'address': RELAYER['address'], 'keyFile': RELAYER['key_file']},
        'handoff': {'url': 'http://127.0.0.1:8491', 'tokenFile': str(token)},
        'stateFile': str(RUNTIME / 'relayer-state.json'),
        'assets': [D['token']], 'marginBlocks': 60, 'maxFee': str(20 * 10**18), 'intervalMs': 3000,
        'pool': pool_pins,
    }
    (RUNTIME / 'relayer-config.json').write_text(json.dumps(relayer, indent=2) + '\n')
(RUNTIME / 'pool-pins.json').write_text(json.dumps(pool_pins, indent=2) + '\n')
print(json.dumps({'prover_config': str(RUNTIME / 'prover-v3.toml'), 'relayer_config': str(RUNTIME / 'relayer-config.json') if RELAYER else None,
                  'bound_data_dir': str(bound_dir), 'pool_pins': pool_pins}, indent=2))
