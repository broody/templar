"""Size gate for the pool classes (implementation review HA-IC5): every contract's CASM bytecode
must fit the sequencer's 80 * 1024-felt declaration limit, with the headroom printed. Run after
`scarb build` in cairo/."""
from pathlib import Path
import json, sys

LIMIT = 80 * 1024
TARGET = Path(__file__).resolve().parent / 'cairo/target/dev'


def main():
    worst = []
    for f in sorted(TARGET.glob('m31_pool_*.compiled_contract_class.json')):
        n = len(json.loads(f.read_text())['bytecode'])
        name = f.name.removeprefix('m31_pool_').removesuffix('.compiled_contract_class.json')
        worst.append((n, name))
        assert n <= LIMIT, f'{name}: CASM {n} felts exceeds the {LIMIT}-felt declaration limit'
    for n, name in sorted(worst, reverse=True)[:3]:
        print(f'{name}: {n} felts, {LIMIT - n} headroom ({100 * n / LIMIT:.1f}%)')


if __name__ == '__main__':
    sys.exit(main())
