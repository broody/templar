// Command exportvk compiles the spend statement, runs a Groth16 setup, and
// writes the verifying key (garaga-compatible gnark JSON), a proof over the
// ordinary fixture bundle, and the 8-scalar public-input vector — the inputs
// to `garaga gen` for the on-chain verifier (ADR-0008/0010/0014).
//
// The setup here is a local test key only; production keys come from the
// public ceremony (ADR-0008).
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"

	circuit "templar/circuit"
)

// ---- minimal fixture plumbing (mirrors statement_test.go) ------------------

type noteJSON struct {
	Inner        string `json:"inner"`
	Salt         string `json:"salt"`
	OwnerPrivKey string `json:"owner_priv"`
	Token        string `json:"token"`
	Amount       int    `json:"amount"`
	Controller   int    `json:"controller"`
	Policy       int    `json:"policy"`
	Leaf         string `json:"leaf"`
	Nullifier    string `json:"nullifier"`
}

type caseJSON struct {
	TreeRoot    string     `json:"tree_root"`
	LeafIndices []int      `json:"leaf_indices"`
	Paths       [][]string `json:"paths"`
	Inputs      []noteJSON `json:"inputs"`
	Outputs     []noteJSON `json:"outputs"`
	Withdrawals []struct {
		Token  string `json:"token"`
		Amount int    `json:"amount"`
	} `json:"withdrawals"`
	Controller           int    `json:"controller"`
	Deadline             int    `json:"deadline"`
	Nonce                int    `json:"nonce"`
	TransitionCommitment string `json:"transition_commitment"`
	Binding              struct {
		ProtocolVersion string `json:"protocol_version"`
		ChainId         string `json:"chain_id"`
		PoolAddress     string `json:"pool_address"`
		ActionsHash     string `json:"actions_hash"`
		Value           string `json:"value"`
	} `json:"binding"`
}

type fixtureJSON struct {
	Ordinary caseJSON `json:"ordinary"`
}

func big_(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 0)
	if !ok {
		panic("bad big int " + s)
	}
	return x
}

func el(v *big.Int) emulated.Element[circuit.StarknetFp] {
	return emulated.ValueOf[circuit.StarknetFp](v)
}

func buildAssignment(c *caseJSON) *circuit.SpendStatement {
	st := &circuit.SpendStatement{
		ProtocolVersion:      el(big_(c.Binding.ProtocolVersion)),
		ChainId:              el(big_(c.Binding.ChainId)),
		PoolAddress:          el(big_(c.Binding.PoolAddress)),
		TreeRoot:             el(big_(c.TreeRoot)),
		Controller:           el(big.NewInt(int64(c.Controller))),
		Deadline:             el(big.NewInt(int64(c.Deadline))),
		TransitionCommitment: el(big_(c.TransitionCommitment)),
		StatementBinding:     el(big_(c.Binding.Value)),
		NIn:                  len(c.Inputs),
		NOut:                 len(c.Outputs),
		NWd:                  len(c.Withdrawals),
		Token:                el(big_(c.Inputs[0].Token)),
		Nonce:                el(big.NewInt(int64(c.Nonce))),
		ActionsHash:          el(big_(c.Binding.ActionsHash)),
	}
	zeroEl := el(big.NewInt(0))
	for i := 0; i < circuit.MAX_IN; i++ {
		st.InSalt[i], st.InOwner[i], st.InAmount[i] = zeroEl, zeroEl, zeroEl
		st.InCtrl[i], st.InPolicy[i], st.Nullifiers[i] = zeroEl, zeroEl, zeroEl
		st.LeafIndices[i] = big.NewInt(0)
		for j := 0; j < circuit.TREE_DEPTH; j++ {
			st.Paths[i][j] = zeroEl
		}
	}
	for j := 0; j < circuit.MAX_OUT; j++ {
		st.OutInner[j], st.OutAmount[j] = zeroEl, zeroEl
		st.OutCtrl[j], st.OutPolicy[j], st.OutCommitments[j] = zeroEl, zeroEl, zeroEl
	}
	for k := 0; k < circuit.MAX_WD; k++ {
		st.WdAmount[k] = zeroEl
	}
	for i, in := range c.Inputs {
		st.InSalt[i] = el(big_(in.Salt))
		st.InOwner[i] = el(big_(in.OwnerPrivKey))
		st.InAmount[i] = el(big.NewInt(int64(in.Amount)))
		st.InCtrl[i] = el(big.NewInt(int64(in.Controller)))
		st.InPolicy[i] = el(big.NewInt(int64(in.Policy)))
		st.Nullifiers[i] = el(big_(in.Nullifier))
		st.LeafIndices[i] = big.NewInt(int64(c.LeafIndices[i]))
		for j, p := range c.Paths[i] {
			st.Paths[i][j] = el(big_(p))
		}
	}
	for j, out := range c.Outputs {
		st.OutInner[j] = el(big_(out.Inner))
		st.OutAmount[j] = el(big.NewInt(int64(out.Amount)))
		st.OutCtrl[j] = el(big.NewInt(int64(out.Controller)))
		st.OutPolicy[j] = el(big.NewInt(int64(out.Policy)))
		st.OutCommitments[j] = el(big_(out.Leaf))
	}
	for k, wd := range c.Withdrawals {
		st.WdAmount[k] = el(big.NewInt(int64(wd.Amount)))
	}
	return st
}

// ---- garaga-compatible gnark vk JSON ---------------------------------------

type g1json struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type fp2json struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}
type g2json struct {
	X fp2json `json:"x"`
	Y fp2json `json:"y"`
}

type vkJSON struct {
	Curve string `json:"curve"`
	G1    struct {
		Alpha g1json   `json:"alpha"`
		Delta g1json   `json:"delta"`
		K     []g1json `json:"K"`
	} `json:"g1"`
	G2 struct {
		Beta  g2json `json:"beta"`
		Gamma g2json `json:"gamma"`
		Delta g2json `json:"delta"`
	} `json:"g2"`
}

func g1(p bn254.G1Affine) g1json {
	return g1json{X: "0x" + p.X.Text(16), Y: "0x" + p.Y.Text(16)}
}

func g2(p bn254.G2Affine) g2json {
	return g2json{
		X: fp2json{A0: "0x" + p.X.A0.Text(16), A1: "0x" + p.X.A1.Text(16)},
		Y: fp2json{A0: "0x" + p.Y.A0.Text(16), A1: "0x" + p.Y.A1.Text(16)},
	}
}

func writeJSON(path string, v any) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}

func main() {
	fmt.Println("compiling statement (4/4/2, depth 32)...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.SpendStatement{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("constraints: %d\n", ccs.GetNbConstraints())

	data, err := os.ReadFile("fixture.json")
	if err != nil {
		panic(err)
	}
	var fx fixtureJSON
	if err := json.Unmarshal(data, &fx); err != nil {
		panic(err)
	}
	ordinary := buildAssignment(&fx.Ordinary)
	w, err := frontend.NewWitness(ordinary, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	fmt.Println("groth16 setup (local test key — not for production)...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		panic(err)
	}
	pubW, err := w.Public()
	if err != nil {
		panic(err)
	}
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		panic(err)
	}
	fmt.Println("local prove+verify OK")

	vkBn := vk.(*groth16bn254.VerifyingKey)
	var out vkJSON
	out.Curve = "bn254"
	out.G1.Alpha = g1(vkBn.G1.Alpha)
	out.G1.Delta = g1(vkBn.G1.Delta)
	for _, k := range vkBn.G1.K {
		out.G1.K = append(out.G1.K, g1(k))
	}
	out.G2.Beta = g2(vkBn.G2.Beta)
	out.G2.Gamma = g2(vkBn.G2.Gamma)
	out.G2.Delta = g2(vkBn.G2.Delta)
	writeJSON("vk.json", out)

	proofBn := proof.(*groth16bn254.Proof)
	proofJSON := map[string]any{
		"curve": "bn254",
		"a":     g1(proofBn.Ar),
		"b":     g2(proofBn.Bs),
		"c":     g1(proofBn.Krs),
	}
	writeJSON("proof.json", proofJSON)

	// The 8-scalar Groth16 public-input vector (ADR-0014), in circuit order.
	c := &fx.Ordinary
	writeJSON("public_inputs.json", []string{
		c.Binding.ProtocolVersion, c.Binding.ChainId, c.Binding.PoolAddress,
		c.TreeRoot, "0x0", "0x0", c.TransitionCommitment, c.Binding.Value,
	})
	fmt.Println("wrote vk.json, proof.json, public_inputs.json")
}
