package circuit

// Circuit-side sponge validation: the hades permutation was validated in
// bench/adr8 (single permutation, proven); the sponge wrapper (absorb +
// parity finalize) is checked here against the same Cairo-VM-validated
// vectors ref_poseidon.py produced for arities 1..8.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

type SpongeCircuit struct {
	In  []emulated.Element[StarknetFp]
	Out emulated.Element[StarknetFp] `gnark:",public"`
}

func (c *SpongeCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[StarknetFp](api)
	if err != nil {
		return err
	}
	span := make([]*emulated.Element[StarknetFp], len(c.In))
	for i := range c.In {
		span[i] = &c.In[i]
	}
	f.AssertIsEqual(HashSpan(f, span), &c.Out)
	return nil
}

func checkSpan(t *testing.T, vals []string, want string) {
	t.Helper()
	// Shape must match: compile a throwaway assignment of the same arity
	// (Compile mutates its argument), then witness with a fresh one.
	shape := &SpongeCircuit{Out: el(mustBig(t, want))}
	for range vals {
		shape.In = append(shape.In, el(big.NewInt(0)))
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape)
	if err != nil {
		t.Fatal(err)
	}
	assign := &SpongeCircuit{Out: el(mustBig(t, want))}
	for _, v := range vals {
		assign.In = append(assign.In, el(mustBig(t, v)))
	}
	w, err := frontend.NewWitness(assign, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("span len %d: circuit sponge != Cairo-VM vector: %v", len(vals), err)
	}
}

func TestSpongeMatchesCairoVM(t *testing.T) {
	hexB := func(i int) string { return "0x" + big.NewInt(int64(i)).Text(16) }
	cases := map[int]string{
		1: "0x18c919558c6971b015d72d736d380b633eeb4f1e58bc2149a1503b3f1ac3d89",
		2: "0x48ab8000e37c46eef014b37d36461567329d4850e47f83336f45038df59f412",
		3: "0x31497a07aed67e853af509beea0c58bcef025d707ca0cdc645b65f45a280fe1",
		4: "0x791628c6a8dc0450bed232b3d6d3bbddd59e09bbd1e0c3e37bcc2ba21cc281a",
		5: "0x7d31af2cd1fde15625b6a45c37de9da3180dc2619453ec81f79ae81525ba725",
		6: "0x7374633ad42559b6badcc0196b9d721c2735cda851409bca45b634275ee96d5",
		7: "0x4a9fe1fd9b2bac5a3b4dd4ea9f3155d83312df090752b7f7712f7df70cfaa90",
		8: "0x61e8045b139912d10b9b219ce5b537ac546bee019728ca1106153b5a47f98b9",
	}
	for n, want := range cases {
		vals := make([]string, n)
		for i := range vals {
			vals[i] = hexB(0x100 + i)
		}
		checkSpan(t, vals, want)
	}
	t.Log("circuit sponge == Cairo VM for arities 1..8")
}

func TestBindingSpongeFixture(t *testing.T) {
	fx := loadFixture(t)
	c := &fx.Ordinary
	vals := []string{
		"0x" + feltShortString("TX_BIND_TAG:V2"), c.Binding.ProtocolVersion,
		c.Binding.ChainId, c.Binding.PoolAddress, c.TreeRoot,
		"0x" + big.NewInt(int64(len(c.Inputs))).Text(16),
	}
	// Padded arrays exactly as spend.cairo compute_statement_binding
	// (ADR-0014): zero-filled to MAX_*; withdrawals as (token, low, high).
	for i := 0; i < MAX_IN; i++ {
		if i < len(c.Inputs) {
			vals = append(vals, c.Inputs[i].Nullifier)
		} else {
			vals = append(vals, "0x0")
		}
	}
	vals = append(vals, "0x"+big.NewInt(int64(len(c.Outputs))).Text(16))
	for j := 0; j < MAX_OUT; j++ {
		if j < len(c.Outputs) {
			vals = append(vals, c.Outputs[j].Leaf)
		} else {
			vals = append(vals, "0x0")
		}
	}
	vals = append(vals, "0x"+big.NewInt(int64(len(c.Withdrawals))).Text(16))
	for k := 0; k < MAX_WD; k++ {
		if k < len(c.Withdrawals) {
			vals = append(vals, c.Withdrawals[k].Token,
				"0x"+big.NewInt(int64(c.Withdrawals[k].Amount)).Text(16), "0x0")
		} else {
			vals = append(vals, "0x0", "0x0", "0x0")
		}
	}
	vals = append(vals,
		"0x"+big.NewInt(int64(c.Controller)).Text(16),
		"0x"+big.NewInt(int64(c.Deadline)).Text(16),
		c.TransitionCommitment,
		c.Binding.ActionsHash,
	)
	checkSpan(t, vals, c.Binding.Value)
	t.Log("binding sponge matches fixture value")
}
