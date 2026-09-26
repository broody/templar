#!/usr/bin/env python3
"""ADR-0027 phase D: the dual-version release's configuration (docs/pool-v3-spec.md §9.5, §10.2,
§11.1 step 3) from `results/deployment.json`.

Writes, in the run directory (nothing is sent):
- `prover-v6.toml`: pool V3 with `r5` (the V5 adapter, served until the swap), `r6` (the R0 routing
  adapter; dormant until the swap), and `p1` routed with P6's P1 adapter as its legacy adapter; the
  bucket check on a reference V6 job; the relayer's handoff; no payment (Sepolia is free);
- `pool-pins-v6.json`: the SDK's pool constants with both generations (`generations.r0`,
  `generations.p1`, `p1Adapter`), the pins the SDK SEPOLIA constant takes;
- `relayer-config-v6.json`: P6's relayer account with those pins.

Usage: configs.py [--bucket-reference DIR]
"""
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_ADR27_RUN', Path.home() / '.local/share/templar/runs/adr27-d'))
P6_RUN = Path.home() / '.local/share/templar/runs/account-bound-p6'
D = json.loads((HERE / 'results/deployment.json').read_text())
P6 = json.loads((ROOT / 'bench/account-bound-p6/results/deployment.json').read_text())
P6_PINS = json.loads((P6_RUN / 'pool-pins.json').read_text())
P6_RELAYER = json.loads((P6_RUN / 'relayer-config.json').read_text())
R5_BRIDGE = Path.home() / '.local/share/templar/runs/r5-p3b/bridge'
R6_BRIDGE = Path.home() / '.local/share/templar/runs/r6-p1/bridge'
P1_BRIDGE = ROOT / 'target/bridge-p1'
LOCAL_RPC = 'http://127.0.0.1:9545/rpc/v0_10'
R6_CIRCUIT = [2010035999, 4123906337, 3936982050, 2269257694, 3115244238, 1536739351, 29337086, 2871661834]
bucket_reference = sys.argv[sys.argv.index('--bucket-reference') + 1] if '--bucket-reference' in sys.argv else None


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def bridge_lines(bridge):
    return (f'bridge_dir = "{bridge}"\nbridge_record_sha256 = "{sha(bridge / "build-record.json")}"\n'
            f'bridge_executable_sha256 = "{sha(bridge / "target/dev/templar_membership_bridge.executable.json")}"\n')


def route_toml(r):
    return (f'[[relation.routes]]\nstatement = "{r["statement"]}"\nstatement_class = "{r["statement_class"]}"\n'
            f'account_tag = "{r["account_tag"]}"\nos_program = "{r["os_program"]}"\nmax_proof_age = {r["max_proof_age"]}\n')


record = json.loads((R6_BRIDGE / 'build-record.json').read_text())
assert record['message_tag'] == 'TMPZR0_PAYMENT_V6' and record['circuit_hash_u32_le'] == R6_CIRCUIT
r6, planned = D['r0_route'], {**D['r0_route'], **D['planned_route']}
p1 = D['p1_route']
token = P6_RUN / 'relay.token'

toml = f'''# Templar prover server: Sepolia, pool V3, dual-version release (ADR-0027 phase D). Written by
# bench/adr27-d/configs.py. r5 serves until the swap; r6 is dormant until the pool's R0 verifier is
# its routing adapter; p1 serves through P6's adapter, then through the P1 routing adapter.
[server]
listen = "127.0.0.1:8490"
data_dir = "{RUNTIME / 'prover/jobs'}"
retention_secs = 7200
max_concurrent_jobs = 1
queue_capacity = 8
blocks_per_job = 60
relay_margin_blocks = 60

[limits]
submissions_per_hour = 30
queued_per_address = 4

[network]
name = "sepolia"
chain_id = "SN_SEPOLIA"
rpc_url = "{LOCAL_RPC}"
pool = "{D['pool']}"
pool_version = 3
os_program = "{P6['r0']['os_program']}"
max_proof_age = {P6['r0']['max_proof_age']}

[[relation]]
name = "r5"
statement_account = "{P6['r0']['statement']}"
statement_class = "{P6['r0']['statement_class']}"
account_tag = "TMPZR0_PAYMENT_V5"
adapter = "{P6['r0_adapter']}"
{bridge_lines(R5_BRIDGE)}
[[relation]]
name = "r6"
statement_account = "{r6['statement']}"
statement_class = "{r6['statement_class']}"
account_tag = "TMPZR0_PAYMENT_V6"
adapter = "{D['r0-routing-adapter']}"
adapter_class = "{D['adapter_class']}"
route_states = [["{r6['statement']}"], ["{r6['statement']}", "{planned['statement']}"]]
{bridge_lines(R6_BRIDGE)}{route_toml(r6)}{route_toml(planned)}
[[relation]]
name = "p1"
statement_account = "{p1['statement']}"
statement_class = "{p1['statement_class']}"
account_tag = "TMPZP1_POLICY_V1"
adapter = "{D['p1-routing-adapter']}"
adapter_class = "{D['adapter_class']}"
legacy_adapter = "{P6['p1_adapter']}"
{bridge_lines(P1_BRIDGE)}{route_toml(p1)}
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
bucket_log_size = 25
{f'bucket_reference = "{bucket_reference}"' if bucket_reference else '# bucket_reference: set with --bucket-reference once a V6 virtual-OS job exists'}
'''
(RUNTIME / 'prover/jobs').mkdir(parents=True, exist_ok=True)
(RUNTIME / 'prover-v6.toml').write_text(toml)


def route_pin(r):
    return {'statement': r['statement'], 'statementClass': r['statement_class'], 'accountTag': r['account_tag'],
            'osProgram': r['os_program'], 'maxProofAge': r['max_proof_age']}


pins = {
    **P6_PINS,
    'p1Adapter': {'adapter': P6['p1_adapter'], 'adapterClass': P6['adapter_class']},
    'generations': {
        'r0': [{
            'relation': 'r6', 'version': 'v6', 'adapter': D['r0-routing-adapter'], 'adapterClass': D['adapter_class'],
            'routing': True, 'circuitHash': R6_CIRCUIT, 'configHash': P6_PINS['configHash'],
            'routes': [route_pin(r6), route_pin(planned)],
            'routeStates': [[r6['statement']], [r6['statement'], planned['statement']]],
            # The drill adds the planned route, then removes it (§11.4 step 3): both are planned.
            'plannedProposals': [{'statement': planned['statement'], 'route': route_pin(planned)},
                                 {'statement': planned['statement'], 'route': None}],
            'primary': r6['statement'],
        }],
        'p1': [{
            'relation': 'p1', 'version': 'v5', 'adapter': D['p1-routing-adapter'], 'adapterClass': D['adapter_class'],
            'routing': True, 'configHash': P6_PINS['configHash'], 'routes': [route_pin(p1)],
            'routeStates': [[p1['statement']]], 'primary': p1['statement'],
        }],
    },
}
(RUNTIME / 'pool-pins-v6.json').write_text(json.dumps(pins, indent=2) + '\n')
relayer = {**P6_RELAYER, 'pool': pins, 'stateFile': str(P6_RUN / 'relayer-state.json')}
(RUNTIME / 'relayer-config-v6.json').write_text(json.dumps(relayer, indent=2) + '\n')
print(json.dumps({'prover_config': str(RUNTIME / 'prover-v6.toml'), 'relayer_config': str(RUNTIME / 'relayer-config-v6.json'),
                  'pool_pins': str(RUNTIME / 'pool-pins-v6.json')}, indent=2))
