"""Check preserved archives and the benchmark's copied proving dependencies."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    archives = json.loads((HERE / 'results/prior-manifests.json').read_text())
    report = {'archives': {}, 'copied_dependencies': {}}
    failures = []
    for relative, expected in archives.items():
        manifest = ROOT / relative
        assert digest(manifest) == expected, f'Changed old manifest: {relative}'
        count = 0
        for line in manifest.read_text().splitlines():
            recorded, filename = line.split('  ', 1)
            path = manifest.parent / filename
            count += 1
            if not path.is_file() or digest(path) != recorded:
                failures.append(str(path.relative_to(ROOT)))
        report['archives'][relative] = {'manifest_sha256': expected, 'checked_files': count}

    copied = ROOT / 'target/m31-tree/copied-source-manifest.json'
    report['copied_source_manifest_sha256'] = digest(copied)
    for tree, files in json.loads(copied.read_text()).items():
        for relative, expected in files.items():
            for base in ['target/wasm-membership', 'target/m31-tree']:
                path = ROOT / base / tree / relative
                if not path.is_file() or digest(path) != expected:
                    failures.append(str(path.relative_to(ROOT)))
        report['copied_dependencies'][tree] = {'files_per_copy': len(files), 'copies_checked': 2}

    report['failures'] = failures
    report['passed'] = not failures
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
