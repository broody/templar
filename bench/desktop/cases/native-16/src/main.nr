fn main(a: Field, b: Field) -> pub Field {
    let mut acc = a;
    for i in 0..16 {
        acc = std::hash::poseidon2_permutation([acc, b + i as Field, 0, 2 * 18446744073709551616], 4)[0];
    }
    acc
}
