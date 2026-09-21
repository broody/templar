package circuit

// Non-native felt252 (Starknet field) arithmetic over BN254 — gnark emulated.
//
// The hades permutation and the poseidon_hash_span sponge below reproduce
// packages/pool/src/hashes.cairo byte-for-byte:
// - hades: x^3 S-box, r_f=8, r_p=83, sha256("Hades"+idx) round constants,
//   MDS [[3,1,1],[1,-1,1],[1,1,-2]] (validated against the Cairo VM via
//   gen_fixture.py / bench/adr8/ref_poseidon.py).
// - sponge: absorb pairs (s0+x, s1+y), finalize hades(s0+1, s1, s2) for even
//   spans and hades(s0+x, s1+1, s2) for odd — validated for arities 1..8
//   against core::poseidon::poseidon_hash_span (cairo_vec scratch test).
//
// Limb config: 4×64 bits (NbLimbs/BitsPerLimb below). 2×126 overflows the
// BN254 scalar field in carry constraints (ADR-0008); 3×84 costs ~5% less.
// Cost: ~47.5k constraints per permutation with this general emulated layer —
// the ADR-0008 upper bound; M2 continues with a custom limb-folding layer
// toward the ~6–8k target.

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)


var FeltModulus = new(big.Int).Add(
	new(big.Int).Lsh(big.NewInt(1), 251),
	new(big.Int).Add(
		new(big.Int).Mul(big.NewInt(17), new(big.Int).Lsh(big.NewInt(1), 192)),
		big.NewInt(1),
	),
)

type StarknetFp struct{}

func (StarknetFp) NbLimbs() uint     { return 4 }
func (StarknetFp) BitsPerLimb() uint { return 64 }
func (StarknetFp) IsPrime() bool     { return true }
func (StarknetFp) Modulus() *big.Int { return FeltModulus }

const (
	rF = 8
	rP = 83
)

var Ark [rF + rP][3]*big.Int

func init() {
	for r := 0; r < rF+rP; r++ {
		for j := 0; j < 3; j++ {
			idx := 3*r + j
			h := sha256.Sum256([]byte(fmt.Sprintf("Hades%d", idx)))
			v := new(big.Int).SetBytes(h[:])
			Ark[r][j] = v.Mod(v, FeltModulus)
		}
	}
}

// hades applies one full Hades permutation in place.
func hades(f *emulated.Field[StarknetFp], st *[3]*emulated.Element[StarknetFp], round int) {
	for j := 0; j < 3; j++ {
		st[j] = f.Add(st[j], f.NewElement(Ark[round][j]))
	}
	cube := func(x *emulated.Element[StarknetFp]) *emulated.Element[StarknetFp] {
		x2 := f.Mul(x, x)
		return f.Mul(x2, x)
	}
	if round < 4 || round >= 4+rP { // full round: cube all three
		for j := 0; j < 3; j++ {
			st[j] = cube(st[j])
		}
	} else { // partial round: cube the last element only
		st[2] = cube(st[2])
	}
	// MDS [[3,1,1],[1,-1,1],[1,1,-2]] — linear, no field multiplications.
	b3 := big.NewInt(3)
	b2 := big.NewInt(2)
	a, b, c := st[0], st[1], st[2]
	r0 := f.Add(f.Add(f.MulConst(a, b3), b), c)
	r1 := f.Add(f.Add(a, f.Neg(b)), c)
	r2 := f.Sub(f.Add(a, b), f.MulConst(c, b2))
	st[0], st[1], st[2] = r0, r1, r2
}

// HashSpan implements core::poseidon::poseidon_hash_span (sponge, validated
// against the Cairo VM for arities 1..8).
func HashSpan(f *emulated.Field[StarknetFp], span []*emulated.Element[StarknetFp]) *emulated.Element[StarknetFp] {
	s0 := f.NewElement(0)
	s1 := f.NewElement(0)
	s2 := f.NewElement(0)
	one := f.NewElement(1)
	i := 0
	for ; i+1 < len(span); i += 2 {
		st := [3]*emulated.Element[StarknetFp]{
			f.Add(s0, span[i]),
			f.Add(s1, span[i+1]),
			s2,
		}
		for r := 0; r < rF+rP; r++ {
			hades(f, &st, r)
		}
		s0, s1, s2 = st[0], st[1], st[2]
	}
	if i < len(span) { // odd remainder: single absorb, capacity +1
		st := [3]*emulated.Element[StarknetFp]{
			f.Add(s0, span[i]),
			f.Add(s1, one),
			s2,
		}
		for r := 0; r < rF+rP; r++ {
			hades(f, &st, r)
		}
		s0, s1, s2 = st[0], st[1], st[2]
	} else { // even finalize
		st := [3]*emulated.Element[StarknetFp]{
			f.Add(s0, one),
			s1,
			s2,
		}
		for r := 0; r < rF+rP; r++ {
			hades(f, &st, r)
		}
		s0, s1, s2 = st[0], st[1], st[2]
	}
	return s0
}
