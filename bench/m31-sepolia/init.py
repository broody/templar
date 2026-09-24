"""Create the private runtime directory for one Sepolia run and point `run-location.json` at it.
No network access. Wallet secrets, captures and signed requests live only there."""
from pathlib import Path
import json, os, secrets, tempfile

HERE = Path(__file__).resolve().parent
assert not (HERE / 'run-location.json').exists(), 'existing run: resume it, do not replace its pointer'
# Persistent and private: /tmp does not survive a reboot (the 2026-09-23 run's runtime was lost).
base = Path.home() / '.local/share/templar/runs'
base.mkdir(parents=True, exist_ok=True)
run = Path(tempfile.mkdtemp(prefix='m31-sepolia-', dir=base))
os.chmod(run, 0o700)
P = 2**31 - 1
digest = lambda: [secrets.randbelow(P - 1) + 1 for _ in range(9)]
wallets = {name: {'sk': digest()} for name in ('alice', 'bob')}
(run / 'private-wallets.json').write_text(json.dumps(wallets) + '\n')
os.chmod(run / 'private-wallets.json', 0o600)
(run / 'manifest.json').write_text(json.dumps({'salt_base': hex(secrets.randbits(248))}, indent=2) + '\n')
(HERE / 'run-location.json').write_text(json.dumps({'runtime': str(run)}, indent=2) + '\n')
print(run)
