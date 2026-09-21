"""Export the experiment's source deltas without copying dependency sources."""
from pathlib import Path
import difflib, json

H = Path(__file__).resolve().parent
E = json.loads((H / 'environment.json').read_text())
W = Path(E['work'])
OLD = Path(json.loads((H.parent / 'prover-memory/environment.json').read_text())['work'])

def patch(items, destination):
    chunks = []
    for old, new, label in items:
        chunks.extend(difflib.unified_diff(old.read_text().splitlines(True),
                      new.read_text().splitlines(True), fromfile='a/' + label,
                      tofile='b/' + label))
    (H / destination).write_text(''.join(chunks))

patch([(OLD / p, W / p, p) for p in [
    'proving-utils/crates/privacy_prove/src/low_memory.rs',
    'sequencer/crates/starknet_transaction_prover/src/proving/prover.rs',
]], 'integration.patch')
for directory, original, output in [
    ('stwo', E['stwo_original'], 'stwo.patch'),
    ('stwo-cairo', E['stwo_cairo_original'], 'stwo-cairo.patch'),
]:
    items = []
    for new in sorted((W / directory).rglob('*.rs')):
        relative = new.relative_to(W / directory)
        if 'target' in relative.parts:
            continue
        old = Path(original) / relative
        assert old.exists(), f'Untracked source requires explicit export: {relative}'
        if old.read_bytes() != new.read_bytes():
            items.append((old, new, str(relative)))
    patch(items, output)
print('Exported Cairo memory source patches.')
