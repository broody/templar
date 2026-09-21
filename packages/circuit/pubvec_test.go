package circuit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// Dumps the actual gnark public witness vector (the Groth16 public wire
// values, in order) for the ordinary fixture bundle — ground truth for the
// on-chain verifier's public-input layout.
func TestDumpPublicVector(t *testing.T) {
	fx := loadFixture(t)
	a := buildAssignment(t, &fx.Ordinary)
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	vec, ok := pubW.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("unexpected vector type %T", pubW.Vector())
	}
	for i, v := range vec {
		fmt.Printf("PUB %d = 0x%s\n", i, v.Text(16))
	}
}
