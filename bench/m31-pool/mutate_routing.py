"""Routing adapter mutants for the phase C review's coverage findings (PV6-C1, PV6-C2, PV6-C3,
ADV-V6-3): each is applied to a copy of `cairo/` and the adapter tests (every test whose name
contains `routing`, the routed P1 pool test included) must kill it.

    python3 mutate_routing.py [RUN_DIR]   # default ~/.local/share/templar/runs/routing-mutants
"""
import json, os, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('~/.local/share/templar/runs/routing-mutants'))
SRC = 'src/routing_adapter.cairo'
PATH = '/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:' + os.environ['PATH']

MUTANTS = [
    ('gate reads the R0 slot for both kinds (PV6-C1)', 'self.pool().get_verifier(self.kind.read())', 'self.pool().get_verifier(R0)'),
    ('removal apply emits nothing (PV6-C2 M2)', '                self.emit(RouteSet { statement, route: Option::None });\n', ''),
    ('removal apply keeps its proposal (PV6-C2 M13)', '                self.clear(statement);\n                self.remove(statement);', '                self.remove(statement);'),
    ('same-key replacement keeps the old value (PV6-C2 M3)', '                    self.proposal_route.write(statement, r);', '                    if old == NONE {\n                        self.proposal_route.write(statement, r);\n                    }'),
    ('verify skips the class re-check (PV6-C3)', "            assert(self.class_of(route.statement) == route.statement_class, 'ROUTE_CLASS');\n", ''),
    ('propose ignores retired keys (ADV-V6-3)', "                    assert(!self.retired.read(statement), 'ROUTE_RETIRED');\n", ''),
    ('removal does not retire (ADV-V6-3)', '                self.retired.write(statement, true);\n', ''),
    ('verify checks every route\'s class (PR-RC-1 B18)',
     "            assert(self.class_of(route.statement) == route.statement_class, 'ROUTE_CLASS');\n",
     "            let mut k = 0;\n            while k < n {\n                let q = self.routes.read(self.route_keys.read(k));\n                assert(self.class_of(q.statement) == q.statement_class, 'ROUTE_CLASS');\n                k += 1;\n            }\n"),
    ('verify checks the first route\'s class (PR-RC-1 B24)',
     "            assert(self.class_of(route.statement) == route.statement_class, 'ROUTE_CLASS');\n",
     "            let first = self.routes.read(self.route_keys.read(0));\n            assert(self.class_of(first.statement) == first.statement_class, 'ROUTE_CLASS');\n"),
    ('verify ignores the route age', "            assert(current - base <= route.max_proof_age, 'PROOF_AGE');\n", ''),
]


def main():
    work = RUN / 'cairo'
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(HERE / 'cairo', work, ignore=shutil.ignore_patterns('target', '.snfoundry_cache'))
    # The copy's path dependencies are relative to cairo/; make them absolute.
    toml = (work / 'Scarb.toml').read_text()
    for line in toml.splitlines():
        if 'path = "' in line:
            rel = line.split('path = "')[1].split('"')[0]
            if not rel.startswith('/'):
                toml = toml.replace(f'path = "{rel}"', f'path = "{(HERE / "cairo" / rel).resolve()}"')
    (work / 'Scarb.toml').write_text(toml)
    original = (work / SRC).read_text()
    rows = []
    for name, old, new in [('unmutated', None, None)] + MUTANTS:
        text = original
        if old is not None:
            assert text.count(old) == 1, (name, text.count(old))
            text = text.replace(old, new)
            assert text != original
        (work / SRC).write_text(text)
        r = subprocess.run(['snforge', 'test', 'routing'], cwd=work, capture_output=True, text=True, env={**os.environ, 'PATH': PATH})
        out = r.stdout + r.stderr
        failed = sorted(l.split()[1] for l in out.splitlines() if l.startswith('[FAIL]'))
        passed = sum(1 for l in out.splitlines() if l.startswith('[PASS]'))
        row = {'mutant': name, 'passed': passed, 'killed_by': failed}
        if passed == 0 and not failed:
            row['error'] = out[-1500:]
        rows.append(row)
        print(json.dumps(row), flush=True)
    (work / SRC).write_text(original)
    assert rows[0]['killed_by'] == [] and rows[0]['passed'] > 0, 'the unmutated tests must pass'
    survivors = [r['mutant'] for r in rows[1:] if not r['killed_by']]
    (HERE / 'results/pool-v3/routing-mutants.json').write_text(json.dumps({'mutants': rows[1:], 'survivors': survivors}, indent=1) + '\n')
    print(json.dumps({'survivors': survivors}))
    assert not survivors


if __name__ == '__main__':
    main()
