package circuit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

// Current-construction path fold alone vs fixture root.
type PathOnly struct {
	Depth     int `gnark:"-"`
	Root      emulated.Element[StarknetFp] `gnark:",public"`
	Leaf      emulated.Element[StarknetFp] `gnark:",public"`
	LeafIndex frontend.Variable
	Path      [TREE_DEPTH]emulated.Element[StarknetFp]
}

func (c *PathOnly) Define(api frontend.API) error {
	f, _ := emulated.NewField[StarknetFp](api)
	depth := TREE_DEPTH
	if c.Depth != 0 {
		depth = c.Depth
	}
	bits := api.ToBinary(c.LeafIndex, TREE_DEPTH)
	cur := &c.Leaf
	for i := 0; i < depth; i++ {
		sib := &c.Path[i]
		curR := f.Reduce(cur)
		left := f.Select(bits[i], sib, curR)
		right := f.Select(bits[i], curR, sib)
		cur = HashSpan(f, []*emulated.Element[StarknetFp]{left, right})
	}
	f.AssertIsEqual(cur, &c.Root)
	return nil
}

func TestProbePathOnly(t *testing.T) {
	fx := loadFixture(t)
	mk := func() *PathOnly {
		c := &PathOnly{
			Root:      el(mustBig(t, fx.Ordinary.TreeRoot)),
			Leaf:      el(mustBig(t, fx.Ordinary.Inputs[0].Leaf)),
			LeafIndex: mustBig(t, "0x"+fmtInt(int64(fx.Ordinary.LeafIndices[0]))),
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
	w, err := frontend.NewWitness(mk(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatal("path-only UNSAT:", err)
	}
	t.Log("path-only (Reduce+Select) OK")
}

func fmtInt(v int64) string { return fmt.Sprintf("%d", v) }
type bigIntAlias = struct{}

func TestPathDepthBisect(t *testing.T) {
	fx := loadFixture(t)
	for _, depth := range []int{26, 28, 30, 31, 32} {
		t.Run(fmt.Sprintf("depth%d", depth), func(t *testing.T) {
			mk := func() *PathOnly {
				c := &PathOnly{
					Depth:     depth,
					Root:      el(mustBig(t, fx.Ordinary.TreeRoot)),
					Leaf:      el(mustBig(t, fx.Ordinary.Inputs[0].Leaf)),
					LeafIndex: mustBig(t, fmt.Sprintf("%d", fx.Ordinary.LeafIndices[0])),
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
			w, err := frontend.NewWitness(mk(), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = ccs.IsSolved(w)
			t.Logf("depth=%d constraints=%d result=%v", depth, ccs.GetNbConstraints(), err)
			if err != nil {
				t.Errorf("depth %d UNSAT: %v", depth, err)
			}
		})
	}
}
