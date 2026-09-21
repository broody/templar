"""Apply archived deltas after setup.py, or verify they are already applied."""
from pathlib import Path
import json, subprocess
H = Path(__file__).resolve().parent
W = Path(json.loads((H / 'environment.json').read_text())['work'])
for directory, name in [('stwo', 'stwo.patch'), ('stwo-cairo', 'stwo-cairo.patch'), ('stwo-circuits', 'stwo-circuits.patch'), ('', 'integration.patch')]:
    cmd = ['patch', '--batch', '-p1', '-i', str(H / name)]
    forward = subprocess.run(cmd + ['--dry-run', '--forward'], cwd=W / directory, capture_output=True)
    if forward.returncode == 0:
        subprocess.run(cmd + ['--forward'], cwd=W / directory, check=True)
    else:
        subprocess.run(cmd + ['--dry-run', '--reverse'], cwd=W / directory, check=True)
print('Experiment patches applied or confirmed.')
