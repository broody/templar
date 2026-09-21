package circuit

// Inner spend statement (spec §7, ADR-0014 shape) — the general bundle:
// up to MAX_IN input notes, MAX_OUT output notes, MAX_WD public withdrawals,
// ordinary or controlled (controller = 0 ⇔ ordinary). Padded fixed-size
// arrays with explicit counts; single-token bundles.
//
// Statement asserts (§7.3):
//  1. per enabled input: note_secret → inner → commitment derivation, and the
//     commitment folds up merkle_path to the public tree_root (the leaf is
//     recomputed from PRIVATE witnesses; input commitments are never public)
//  2. per enabled input: H(NULLIFIER_TAG, note_secret) == nullifier witness,
//     pinned to the contract's input_nullifiers via the binding
//  3. per enabled output: opening recomputes to the commitment witness,
//     pinned to output_commitments via the binding
//  4. controller consistency: every enabled leg's controller field equals the
//     public controller
//  5. conservation (single-token bundle): Σ in == Σ out + Σ withdrawals
//  6. binding: H(TX_BIND_TAG, padded §7.2 fields + counts, actions_hash) ==
//     statement_binding; for controlled bundles the transition_commitment is
//     recomputed over the padded legs + deadline + nonce (§6, ADR-0014)
//
// Groth16 public inputs are the 8 scalars (ADR-0014): version, chain, pool,
// root, controller, deadline, transition_commitment, statement_binding. All
// arrays enter via the binding, which the contract recomputes from calldata.

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

const (
	TREE_DEPTH = 32
	MAX_IN     = 4
	MAX_OUT    = 4
	MAX_WD     = 2
)

type SpendStatement struct {
	// Public inputs (8 scalars, §7.2 + ADR-0014).
	ProtocolVersion      emulated.Element[StarknetFp] `gnark:",public"`
	ChainId              emulated.Element[StarknetFp] `gnark:",public"`
	PoolAddress          emulated.Element[StarknetFp] `gnark:",public"`
	TreeRoot             emulated.Element[StarknetFp] `gnark:",public"`
	Controller           emulated.Element[StarknetFp] `gnark:",public"`
	Deadline             emulated.Element[StarknetFp] `gnark:",public"`
	TransitionCommitment emulated.Element[StarknetFp] `gnark:",public"`
	StatementBinding     emulated.Element[StarknetFp] `gnark:",public"`

	// Native witnesses: slot counts and path indices.
	NIn  frontend.Variable
	NOut frontend.Variable
	NWd  frontend.Variable

	// Scalar element witnesses (must precede all element arrays — gnark
	// v0.16.3 misaligns the witness vector when an array of Elements is
	// declared before other Element witness fields).
	Token emulated.Element[StarknetFp] // single-token bundle (ADR-0014)
	Nonce emulated.Element[StarknetFp] // controller nonce (controlled txs only)

	LeafIndices [MAX_IN]frontend.Variable

	// Padded note/withdrawal witnesses. Slots ≥ count are unenforced padding;
	// the binding pins them to zero (the contract pads with zeros).
	InSalt    [MAX_IN]emulated.Element[StarknetFp]
	InOwner   [MAX_IN]emulated.Element[StarknetFp]
	InAmount  [MAX_IN]emulated.Element[StarknetFp]
	InCtrl    [MAX_IN]emulated.Element[StarknetFp]
	InPolicy  [MAX_IN]emulated.Element[StarknetFp]
	OutInner  [MAX_OUT]emulated.Element[StarknetFp] // invoice commitment; recipient secrets stay recipient-side
	OutAmount [MAX_OUT]emulated.Element[StarknetFp]
	OutCtrl   [MAX_OUT]emulated.Element[StarknetFp]
	OutPolicy [MAX_OUT]emulated.Element[StarknetFp]
	WdAmount  [MAX_WD]emulated.Element[StarknetFp]

	// Witnesses pinned to the contract's arrays by the binding equality.
	Nullifiers     [MAX_IN]emulated.Element[StarknetFp]
	OutCommitments [MAX_OUT]emulated.Element[StarknetFp]
	ActionsHash    emulated.Element[StarknetFp]
	Paths          [MAX_IN][TREE_DEPTH]emulated.Element[StarknetFp]
}

// Domain tags — literal felt252 short strings, pinned in spec §3.1 (V3 note
// family per ADR-0011/0012; binding family V2).
var (
	TagNoteSecret = mustTag("NOTE_SECRET_TAG:V3")
	TagNoteInner  = mustTag("NOTE_INNER_TAG:V3")
	TagCommitment = mustTag("COMMITMENT_TAG:V3")
	TagNullifier  = mustTag("NULLIFIER_TAG:V3")
	TagTransition = mustTag("TRANSITION_COMMIT_TAG:V2")
	TagTxBind     = mustTag("TX_BIND_TAG:V2")
)

func mustTag(s string) *big.Int {
	v, ok := new(big.Int).SetString(feltShortString(s), 16)
	if !ok {
		panic("bad tag")
	}
	return v
}

// feltShortString encodes a ≤31-byte ASCII string the way Cairo short strings
// do: big-endian bytes as an integer (0x-prefixed hex of the byte string).
func feltShortString(s string) string {
	hex := ""
	for _, b := range []byte(s) {
		hex += fmtByte(b)
	}
	return hex
}

func fmtByte(b byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{hexDigits[b>>4], hexDigits[b&0xf]})
}

// noteOpening recomputes the V3 derivation chain (spec §3.1):
// note_secret = H(NS_TAG, salt, owner), inner = H(NI_TAG, note_secret),
// leaf = H(CM_TAG, token, amount, controller, policy, inner).
func noteOpening(f *emulated.Field[StarknetFp], token, salt, owner, amount, ctrl, policy *emulated.Element[StarknetFp]) (secret, leaf *emulated.Element[StarknetFp]) {
	secret = HashSpan(f, []*emulated.Element[StarknetFp]{
		f.NewElement(TagNoteSecret), salt, owner,
	})
	inner := HashSpan(f, []*emulated.Element[StarknetFp]{
		f.NewElement(TagNoteInner), secret,
	})
	leaf = noteCommitment(f, token, amount, ctrl, policy, inner)
	return
}

// noteCommitment is shared by input openings and public invoice outputs.
func noteCommitment(f *emulated.Field[StarknetFp], token, amount, ctrl, policy, inner *emulated.Element[StarknetFp]) *emulated.Element[StarknetFp] {
	return HashSpan(f, []*emulated.Element[StarknetFp]{f.NewElement(TagCommitment), token, amount, ctrl, policy, inner})
}

// enabled returns a native bit: 1 iff slot i < count.
func enabled(api frontend.API, count frontend.Variable, i int) frontend.Variable {
	cmp := api.Cmp(count, i) // 1 iff count > i
	return api.IsZero(api.Sub(1, cmp))
}

// assertEqualWhen asserts a == b only when cond is 1.
func assertEqualWhen(f *emulated.Field[StarknetFp], cond frontend.Variable, a, b *emulated.Element[StarknetFp]) {
	f.AssertIsEqual(f.Select(cond, a, b), b)
}

// elementFromNative lifts a small native value (< 2^64) into an emulated
// element with exact limb semantics (felt252 flattening in the binding).
func elementFromNative(v frontend.Variable) *emulated.Element[StarknetFp] {
	return &emulated.Element[StarknetFp]{Limbs: []frontend.Variable{v, 0, 0, 0}}
}

// assertU128 enforces note/withdrawal amounts < 2^128. Load-bearing: it keeps
// conservation sums wrap-free (Σ < 2^132 << p) and matches the Cairo u128
// note amounts.
func assertU128(api frontend.API, f *emulated.Field[StarknetFp], x *emulated.Element[StarknetFp]) {
	bits := f.ToBits(x)
	var acc frontend.Variable = 0
	for i := 128; i < len(bits); i++ {
		acc = api.Or(acc, bits[i])
	}
	api.AssertIsEqual(acc, 0)
}

// isZeroEmulated returns a native bit: 1 iff x is zero (limbwise, reduced).
// NB: limbs are NOT boolean — accumulate with Add (sum < 2^66, no wrap),
// never Or, which would boolean-constrain them.
func isZeroEmulated(api frontend.API, f *emulated.Field[StarknetFp], x *emulated.Element[StarknetFp]) frontend.Variable {
	r := f.Reduce(x)
	acc := frontend.Variable(0)
	for _, l := range r.Limbs {
		acc = api.Add(acc, l)
	}
	return api.IsZero(acc)
}

// merkleFold folds a (private) leaf up the path; bit i of index selects the
// side (LSB-first, matching tree.cairo). Select inputs are reduced first —
// sponge outputs are lazy non-normal-form and f.Select does not auto-reduce.
func merkleFold(api frontend.API, f *emulated.Field[StarknetFp], leaf *emulated.Element[StarknetFp], index frontend.Variable, path *[TREE_DEPTH]emulated.Element[StarknetFp]) *emulated.Element[StarknetFp] {
	bits := api.ToBinary(index, TREE_DEPTH)
	cur := leaf
	for i := 0; i < TREE_DEPTH; i++ {
		sib := &path[i]
		curR := f.Reduce(cur)
		left := f.Select(bits[i], sib, curR)
		right := f.Select(bits[i], curR, sib)
		cur = HashSpan(f, []*emulated.Element[StarknetFp]{left, right})
	}
	return cur
}

func (c *SpendStatement) Define(api frontend.API) error {
	f, err := emulated.NewField[StarknetFp](api)
	if err != nil {
		return err
	}
	zero := f.NewElement(0)

	// Counts are range-bound by construction (≤ 4, three bits).
	api.AssertIsLessOrEqual(c.NIn, MAX_IN)
	api.AssertIsLessOrEqual(c.NOut, MAX_OUT)
	api.AssertIsLessOrEqual(c.NWd, MAX_WD)

	sumIn := zero
	sumOut := zero

	// --- inputs (§7.3.1/2) -------------------------------------------------
	for i := 0; i < MAX_IN; i++ {
		e := enabled(api, c.NIn, i)
		secret, leaf := noteOpening(f, &c.Token, &c.InSalt[i], &c.InOwner[i], &c.InAmount[i], &c.InCtrl[i], &c.InPolicy[i])
		root := merkleFold(api, f, leaf, c.LeafIndices[i], &c.Paths[i])
		assertEqualWhen(f, e, root, &c.TreeRoot)

		nullifier := HashSpan(f, []*emulated.Element[StarknetFp]{
			f.NewElement(TagNullifier), secret,
		})
		assertEqualWhen(f, e, nullifier, &c.Nullifiers[i])
		// controller consistency (§7.3.4) on enabled legs
		assertEqualWhen(f, e, &c.InCtrl[i], &c.Controller)

		sumIn = f.Add(sumIn, f.Select(e, &c.InAmount[i], zero))
	}

	// --- outputs (§7.3.3) --------------------------------------------------
	for j := 0; j < MAX_OUT; j++ {
		e := enabled(api, c.NOut, j)
		leaf := noteCommitment(f, &c.Token, &c.OutAmount[j], &c.OutCtrl[j], &c.OutPolicy[j], &c.OutInner[j])
		assertEqualWhen(f, e, leaf, &c.OutCommitments[j])
		assertEqualWhen(f, e, &c.OutCtrl[j], &c.Controller)
		sumOut = f.Add(sumOut, f.Select(e, &c.OutAmount[j], zero))
	}

	// --- withdrawals + conservation (§7.3.5, single token) -----------------
	sumWd := zero
	for k := 0; k < MAX_WD; k++ {
		e := enabled(api, c.NWd, k)
		assertU128(api, f, f.Select(e, &c.WdAmount[k], zero))
		sumWd = f.Add(sumWd, f.Select(e, &c.WdAmount[k], zero))
	}
	for i := 0; i < MAX_IN; i++ {
		assertU128(api, f, f.Select(enabled(api, c.NIn, i), &c.InAmount[i], zero))
	}
	for j := 0; j < MAX_OUT; j++ {
		assertU128(api, f, f.Select(enabled(api, c.NOut, j), &c.OutAmount[j], zero))
	}
	f.AssertIsEqual(sumIn, f.Add(sumOut, sumWd))

	// --- binding (§7.3.6, padded + counts, ADR-0014) ------------------------
	// [tag, version, chain, pool, root, nIn, nullifiers[4], nOut,
	//  commitments[4], nWd, (token, low, high)[2], controller, deadline,
	//  transition_commitment, actions_hash]
	preimage := []*emulated.Element[StarknetFp]{
		f.NewElement(TagTxBind), &c.ProtocolVersion, &c.ChainId,
		&c.PoolAddress, &c.TreeRoot, elementFromNative(c.NIn),
	}
	for i := 0; i < MAX_IN; i++ {
		preimage = append(preimage, &c.Nullifiers[i])
	}
	preimage = append(preimage, elementFromNative(c.NOut))
	for j := 0; j < MAX_OUT; j++ {
		preimage = append(preimage, &c.OutCommitments[j])
	}
	preimage = append(preimage, elementFromNative(c.NWd))
	for k := 0; k < MAX_WD; k++ {
		e := enabled(api, c.NWd, k)
		preimage = append(preimage, f.Select(e, &c.Token, zero), &c.WdAmount[k], zero)
	}
	preimage = append(preimage, &c.Controller, &c.Deadline, &c.TransitionCommitment, &c.ActionsHash)
	binding := HashSpan(f, preimage)
	f.AssertIsEqual(binding, &c.StatementBinding)

	// --- transition commitment (§6, controlled bundles only) ----------------
	// [tag, version, chain, pool, nIn, nullifiers[4], inAmounts[4], nOut,
	//  commitments[4], outAmounts[4], nWd, (token, low, high)[2], controller,
	//  deadline, nonce]
	tcPre := []*emulated.Element[StarknetFp]{
		f.NewElement(TagTransition), &c.ProtocolVersion, &c.ChainId,
		&c.PoolAddress, elementFromNative(c.NIn),
	}
	for i := 0; i < MAX_IN; i++ {
		tcPre = append(tcPre, &c.Nullifiers[i], &c.InAmount[i])
	}
	tcPre = append(tcPre, elementFromNative(c.NOut))
	for j := 0; j < MAX_OUT; j++ {
		tcPre = append(tcPre, &c.OutCommitments[j], &c.OutAmount[j])
	}
	tcPre = append(tcPre, elementFromNative(c.NWd))
	for k := 0; k < MAX_WD; k++ {
		e := enabled(api, c.NWd, k)
		tcPre = append(tcPre, f.Select(e, &c.Token, zero), &c.WdAmount[k], zero)
	}
	tcPre = append(tcPre, &c.Controller, &c.Deadline, &c.Nonce)
	tcHash := HashSpan(f, tcPre)

	// Ordinary bundles: tc is unconstrained here (the contract pins it to 0).
	// Controlled bundles: tc must commit to exactly these legs.
	controllerIsZero := isZeroEmulated(api, f, &c.Controller)
	assertEqualWhen(f, api.Sub(1, controllerIsZero), tcHash, &c.TransitionCommitment)

	return nil
}
