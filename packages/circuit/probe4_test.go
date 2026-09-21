package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

// FlatIn + N unused public elements — isolates the unused-public trigger.
type FlatWithUnused struct {
	Nullifier emulated.Element[StarknetFp]   `gnark:",public"`
	Root      emulated.Element[StarknetFp]   `gnark:",public"`
	Unused    [8]emulated.Element[StarknetFp] `gnark:",public"`
	LeafIndex frontend.Variable
	InToken   emulated.Element[StarknetFp]
	InSalt    emulated.Element[StarknetFp]
	InOwner   emulated.Element[StarknetFp]
	InAmount  emulated.Element[StarknetFp]
	InCtrl    emulated.Element[StarknetFp]
	InPolicy  emulated.Element[StarknetFp]
	Path      [TREE_DEPTH]emulated.Element[StarknetFp]
}

func (c *FlatWithUnused) Define(api frontend.API) error {
	f, _ := emulated.NewField[StarknetFp](api)
	ns, leaf := noteOpening(f, &c.InToken, &c.InSalt, &c.InOwner, &c.InAmount, &c.InCtrl, &c.InPolicy)
	null := HashSpan(f, []*emulated.Element[StarknetFp]{f.NewElement(TagNullifier), ns})
	f.AssertIsEqual(null, &c.Nullifier)

	bits := api.ToBinary(c.LeafIndex, TREE_DEPTH)
	cur := leaf
	for i := 0; i < TREE_DEPTH; i++ {
		sib := &c.Path[i]
		curR := f.Reduce(cur)
		left := f.Select(bits[i], sib, curR)
		right := f.Select(bits[i], curR, sib)
		cur = HashSpan(f, []*emulated.Element[StarknetFp]{left, right})
	}
	f.AssertIsEqual(cur, &c.Root)
	return nil
}

func TestFlatWithUnused(t *testing.T) {
	fx := loadFixture(t)
	mk := func() *FlatWithUnused {
		c := &FlatWithUnused{
			Nullifier: el(mustBig(t, fx.Ordinary.Inputs[0].Nullifier)),
			Root:      el(mustBig(t, fx.Ordinary.TreeRoot)),
			LeafIndex: big.NewInt(int64(fx.Ordinary.LeafIndices[0])),
			InToken:   el(mustBig(t, fx.Ordinary.Inputs[0].Token)),
			InSalt:    el(mustBig(t, fx.Ordinary.Inputs[0].Salt)),
			InOwner:   el(mustBig(t, fx.Ordinary.Inputs[0].OwnerPrivKey)),
			InAmount:  el(big.NewInt(int64(fx.Ordinary.Inputs[0].Amount))),
			InCtrl:    el(big.NewInt(int64(fx.Ordinary.Inputs[0].Controller))),
			InPolicy:  el(big.NewInt(int64(fx.Ordinary.Inputs[0].Policy))),
		}
		for i := range c.Unused {
			c.Unused[i] = el(big.NewInt(int64(i + 1)))
		}
		for i, p := range fx.Ordinary.Paths[0] {
			c.Path[i] = el(mustBig(t, p))
		}
		return c
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, mk())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("constraints: %d", ccs.GetNbConstraints())
	w, err := frontend.NewWitness(mk(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatal("flat+unused UNSAT:", err)
	}
	t.Log("flat+unused-publics OK")
}
