package main

// ADR-0008 benchmark: Starknet (felt252) Poseidon permutation expressed in
// non-native arithmetic over BN254, measured in gnark for both Groth16 and
// PLONK. The circuit proves knowledge of (a,b) such that Out = H(a,b) =
// hades_permutation([a,b,2])[0] — the canonical Starknet two-element hash
// (cairo-lang poseidon_hash.py), validated against corelib's
// poseidon_hash_span test vector by ref_poseidon.py.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test/unsafekzg"
)

// felt252 prime: 2^251 + 17*2^192 + 1
var feltModulus = new(big.Int).Add(
	new(big.Int).Lsh(big.NewInt(1), 251),
	new(big.Int).Add(
		new(big.Int).Mul(big.NewInt(17), new(big.Int).Lsh(big.NewInt(1), 192)),
		big.NewInt(1),
	),
)

// Limb config is set per-run via flags; the type's methods read them so a
// single generic instantiation serves all configs (circuit is re-compiled
// per config anyway).
var flagLimbs = flag.Int("limbs", 2, "emulated limbs")
var flagBits = flag.Int("bits", 126, "bits per limb")
var flagProof = flag.String("proof", "both", "groth16 | plonk | both")
var flagTV = flag.String("tv", "tv.json", "test vector json {a,b,out}")

type StarknetFp struct{}

func (StarknetFp) NbLimbs() uint     { return uint(*flagLimbs) }
func (StarknetFp) BitsPerLimb() uint { return uint(*flagBits) }
func (StarknetFp) IsPrime() bool     { return true }
func (StarknetFp) Modulus() *big.Int { return feltModulus }

const (
	rF = 8  // full rounds
	rP = 83 // partial rounds
)

// ark[round][j] = sha256("Hades" + idx) mod P, idx = 3*round + j
// (cairo-lang poseidon_utils.generate_round_constant, fn name "Hades").
var ark [rF + rP][3]*big.Int

func init() {
	p := new(big.Int).Mod(new(big.Int).SetInt64(1), feltModulus)
	_ = p
	for r := 0; r < rF+rP; r++ {
		for j := 0; j < 3; j++ {
			idx := 3*r + j
			h := sha256.Sum256([]byte(fmt.Sprintf("Hades%d", idx)))
			v := new(big.Int).SetBytes(h[:])
			ark[r][j] = v.Mod(v, feltModulus)
		}
	}
}

type PoseidonCircuit struct {
	A   emulated.Element[StarknetFp]
	B   emulated.Element[StarknetFp]
	Out emulated.Element[StarknetFp] `gnark:",public"`
}

func cube(f *emulated.Field[StarknetFp], x *emulated.Element[StarknetFp]) *emulated.Element[StarknetFp] {
	x2 := f.Mul(x, x) // non-native mul #1
	return f.Mul(x2, x)
}

func mds(f *emulated.Field[StarknetFp], st *[3]*emulated.Element[StarknetFp]) {
	// [[3,1,1],[1,-1,1],[1,1,-2]] — linear, no field multiplications.
	b3 := big.NewInt(3)
	b2 := big.NewInt(2)
	a, b, c := st[0], st[1], st[2]
	r0 := f.Add(f.Add(f.MulConst(a, b3), b), c)
	r1 := f.Add(f.Add(a, f.Neg(b)), c)
	r2 := f.Sub(f.Add(a, b), f.MulConst(c, b2))
	st[0], st[1], st[2] = r0, r1, r2
}

func (c *PoseidonCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[StarknetFp](api)
	if err != nil {
		return err
	}
	st := [3]*emulated.Element[StarknetFp]{&c.A, &c.B, f.NewElement(2)}
	round := 0
	for i := 0; i < rF/2; i++ { // 4 full
		for j := 0; j < 3; j++ {
			st[j] = f.Add(st[j], f.NewElement(ark[round][j]))
		}
		for j := 0; j < 3; j++ {
			st[j] = cube(f, st[j])
		}
		mds(f, &st)
		round++
	}
	for i := 0; i < rP; i++ { // 83 partial
		for j := 0; j < 3; j++ {
			st[j] = f.Add(st[j], f.NewElement(ark[round][j]))
		}
		st[2] = cube(f, st[2])
		mds(f, &st)
		round++
	}
	for i := 0; i < rF/2; i++ { // 4 full
		for j := 0; j < 3; j++ {
			st[j] = f.Add(st[j], f.NewElement(ark[round][j]))
		}
		for j := 0; j < 3; j++ {
			st[j] = cube(f, st[j])
		}
		mds(f, &st)
		round++
	}
	f.AssertIsEqual(st[0], &c.Out)
	return nil
}

type tvJSON struct {
	A, B, Out string
}

func loadTV() (a, b, out *big.Int) {
	data, err := os.ReadFile(*flagTV)
	if err != nil {
		panic(err)
	}
	var tv map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&tv); err != nil {
		panic(err)
	}
	mustBig := func(v interface{}) *big.Int {
		s, ok := v.(string)
		if !ok {
			n, ok := v.(json.Number)
			if !ok {
				panic("unexpected tv type")
			}
			s = n.String()
		}
		x, ok := new(big.Int).SetString(s, 0)
		if !ok {
			panic("bad big int " + s)
		}
		return x
	}
	return mustBig(tv["a"]), mustBig(tv["b"]), mustBig(tv["out"])
}

func buildWitness(a, b, out *big.Int) (full, public witness.Witness) {
	assignment := &PoseidonCircuit{
		A:   emulated.ValueOf[StarknetFp](a),
		B:   emulated.ValueOf[StarknetFp](b),
		Out: emulated.ValueOf[StarknetFp](out),
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	pw, err := w.Public()
	if err != nil {
		panic(err)
	}
	return w, pw
}

func sizeOf(w io.WriterTo) int {
	var buf countWriter
	w.WriteTo(&buf)
	return int(buf.n)
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func run(label string, fn func()) time.Duration {
	t0 := time.Now()
	fn()
	d := time.Since(t0)
	fmt.Printf("  %-28s %v\n", label, d.Round(time.Millisecond))
	return d
}

func main() {
	flag.Parse()
	fmt.Printf("config: limbs=%d bits=%d | cpus=%d | proof=%s\n", *flagLimbs, *flagBits, runtime.NumCPU(), *flagProof)

	a, b, out := loadTV()

	// Correctness first: a witness with a wrong Out must fail.
	wrong := new(big.Int).Add(out, big.NewInt(1))
	wf, _ := buildWitness(a, b, wrong)
	ccs0, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PoseidonCircuit{})
	if err != nil {
		fmt.Println("compile failed:", err)
		os.Exit(1)
	}
	if err := ccs0.IsSolved(wf); err == nil {
		fmt.Println("FATAL: wrong witness solved the circuit — reference mismatch")
		os.Exit(1)
	}
	fmt.Println("negative check: wrong Out rejected OK")

	// Real witness.
	assignment := &PoseidonCircuit{
		A:   emulated.ValueOf[StarknetFp](a),
		B:   emulated.ValueOf[StarknetFp](b),
		Out: emulated.ValueOf[StarknetFp](out),
	}

	wFull, wPublic := buildWitness(a, b, out)

	if *flagProof == "groth16" || *flagProof == "both" {
		fmt.Println("groth16 (BN254, R1CS):")
		var ccs constraint.ConstraintSystem
		run("compile (r1cs)", func() {
			var err error
			ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, assignment)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf("  constraints: %d (internal %d, secret %d, public %d)\n",
			ccs.GetNbConstraints(), ccs.GetNbInternalVariables(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables())
		var pk groth16.ProvingKey
		var vk groth16.VerifyingKey
		run("setup (per-circuit)", func() {
			var err error
			pk, vk, err = groth16.Setup(ccs)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf("  vk size: %d B\n", sizeOf(vk))
		var proof groth16.Proof
		run("prove", func() {
			var err error
			proof, err = groth16.Prove(ccs, pk, wFull)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf("  proof size: %d B\n", sizeOf(proof))
		run("verify", func() {
			if err := groth16.Verify(proof, vk, wPublic); err != nil {
				panic(err)
			}
		})
	}

	if *flagProof == "plonk" || *flagProof == "both" {
		fmt.Println("plonk (BN254, SCS, unsafe/test SRS):")
		var ccs constraint.ConstraintSystem
		run("compile (scs)", func() {
			var err error
			ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, assignment)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf("  constraints: %d (internal %d, secret %d, public %d)\n",
			ccs.GetNbConstraints(), ccs.GetNbInternalVariables(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables())
		srs, srsLag, err := unsafekzg.NewSRS(ccs)
		if err != nil {
			panic(err)
		}
		var pk plonk.ProvingKey
		var vk plonk.VerifyingKey
		run("setup (universal SRS reuse)", func() {
			pk, vk, err = plonk.Setup(ccs, srs, srsLag)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf("  vk size: %d B\n", sizeOf(vk))
		var proof plonk.Proof
		run("prove", func() {
			proof, err = plonk.Prove(ccs, pk, wFull)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf("  proof size: %d B\n", sizeOf(proof))
		run("verify", func() {
			if err := plonk.Verify(proof, vk, wPublic); err != nil {
				panic(err)
			}
		})
	}
}
