"""Isolate the measured server bridge and replace only M31 inversion.

The standard Cairo u256 modular-inverse primitive validates its multiplication
guarantees. Canonical conversion and a second M31 product check are explicit.
The proof statement, transcript, PCS parameters and trusted root are unchanged.
"""
from pathlib import Path
import hashlib, json, shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORK = ROOT / 'target/m31-private-wrapper/optimized-cairo'
SOURCE = ROOT / 'target/m31-private-wrapper/server-cairo'


def main():
    assert not WORK.exists(), 'Use a fresh experiment directory'
    shutil.copytree(SOURCE, WORK, ignore=shutil.ignore_patterns('target'))
    rel = 'vendor/verifier_core/src/fields/m31/naive.cairo'
    path = WORK / rel
    original = path.read_text()
    start = original.index('        let t0 = repeated_square')
    end = original.index('\n    }', start)
    changed = original[:start] + '''        let value: u32 = self.into();
        let inverse: u256 = core::math::u256_inv_mod(
            value.into(), 0x7fffffff,
        ).expect('M31 inverse').into();
        let inverse_u32: u32 = inverse.try_into().expect('M31 inverse range');
        let result: M31 = inverse_u32.try_into().expect('M31 inverse canonical');
        assert!(self * result == M31Trait::new(1), "M31 inverse product");
        result''' + original[end:]
    path.write_text(changed)
    # Test the changed primitive directly, including rejection of zero.
    with path.open('a') as f:
        f.write('''
#[cfg(test)]
mod inverse_regression {
    use super::*;
    #[test]
    fn canonical_inverse_products() {
        let values = array![1_u32, 2, 3, 7, 31, 65535, 65536, 1073741824, 2147483645, 2147483646];
        for value in values {
            let a: M31 = value.try_into().unwrap();
            let b = a.inverse();
            assert!(a * b == M31Trait::new(1));
            assert!(b.inverse() == a);
        };
    }
    #[test]
    #[should_panic]
    fn zero_inverse_rejected() {
        let zero: M31 = 0_u32.try_into().unwrap();
        zero.inverse();
    }
}
''')
    out = HERE.parent / 'results/bridge-capacity/optimized'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'source-change.json').write_text(json.dumps({
        'scope': 'same trusted server hash circuit, checked M31 inversion implementation',
        'original_sha256': hashlib.sha256(original.encode()).hexdigest(),
        'changed_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'source': str(SOURCE / rel), 'changed': str(path),
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
