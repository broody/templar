package circuit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestDumpFailing(t *testing.T) {
	fx := loadFixture(t)
	ccsRaw, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, buildAssignment(t, &fx.Ordinary))
	if err != nil {
		t.Fatal(err)
	}
	if r1, ok := ccsRaw.(constraint.R1CS[constraint.U64]); ok {
		cs := r1.GetR1Cs()
		for _, idx := range []int{5314599, 5314598, 5314600, 5314580, 5314620, 5314650} {
			if idx < len(cs) {
				fmt.Printf("#%d: %s\n", idx, cs[idx].String(r1))
			}
		}
	}
}
