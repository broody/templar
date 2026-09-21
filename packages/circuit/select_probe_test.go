package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

type SelProbe struct {
	Bit   frontend.Variable
	A     emulated.Element[StarknetFp] `gnark:",public"`
	B     emulated.Element[StarknetFp] `gnark:",public"`
	Out   emulated.Element[StarknetFp] `gnark:",public"`
}

func (c *SelProbe) Define(api frontend.API) error {
	f, _ := emulated.NewField[StarknetFp](api)
	f.AssertIsEqual(f.Select(c.Bit, &c.A, &c.B), &c.Out)
	return nil
}

// Documents f.Select semantics: which argument does selector=1 pick?
func TestSelectSemantics(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &SelProbe{})
	if err != nil {
		t.Fatal(err)
	}
	probe := func(bit int64, a, b, out *big.Int, label string) {
		w, err := frontend.NewWitness(&SelProbe{
			Bit: big.NewInt(bit), A: el(a), B: el(b), Out: el(out),
		}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = ccs.IsSolved(w)
		t.Logf("%s: Select(1, A, B) with bit=%d -> %v", label, bit, err == nil)
	}
	// bit=1, Out=A must solve iff Select(1,a,b)=a
	probe(1, big.NewInt(11), big.NewInt(22), big.NewInt(11), "Out=A,bit=1")
	probe(1, big.NewInt(11), big.NewInt(22), big.NewInt(22), "Out=B,bit=1")
	probe(0, big.NewInt(11), big.NewInt(22), big.NewInt(11), "Out=A,bit=0")
	probe(0, big.NewInt(11), big.NewInt(22), big.NewInt(22), "Out=B,bit=0")
}
