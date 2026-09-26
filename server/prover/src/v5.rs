//! R0 V5 (`docs/account-bound-note-spec.md` §5): the statement's binding and the job's pool
//! calldata, which the server parses strictly and matches to the statement before it proves
//! (AB-P28). Only ordinary spends (account 0) are served (ADR-0027). Every encoding here is the
//! Cairo code's: the bridge's `binding` module (`client-port/cairo-r5/bridge`), pool V3's
//! `spend5::Spend` and `open_note::hash_intent_of`, and `spend::delivery_digest`
//! (`bench/m31-pool/cairo`).
use anyhow::{bail, ensure, Context, Result};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use crate::rpc::{short_string, sn_keccak};

/// Most felts a pool call may carry: a spend with an invoke of 64 calldata felts and two
/// destinations is about 170.
pub const MAX_POOL_CALL_FELTS: usize = 512;
const MAX_INTENT_CALLDATA: usize = 64;
const MAX_DESTINATIONS: usize = 2;
pub const INVOKE: u64 = 0;
pub const COMPUTE: u64 = 1;

fn two_pow(bits: u32) -> Felt {
    Felt::TWO.pow(bits as u128)
}

fn below(x: &Felt, bits: u32) -> bool {
    *x < two_pow(bits)
}

/// The felt as a u64, if it is one.
pub fn to_u64(x: &Felt) -> Option<u64> {
    let b = x.to_bytes_be();
    b[..24].iter().all(|v| *v == 0).then(|| u64::from_be_bytes(b[24..].try_into().unwrap()))
}

/// A V5 statement's fields, as the bridge decodes and checks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementV5 {
    pub chain: Felt,
    pub pool: Felt,
    pub token_out: Felt,
    pub root: Vec<Felt>,
    pub nullifiers: [Vec<Felt>; 2],
    pub commitments: [Vec<Felt>; 2],
    pub deliveries: [Felt; 2],
    pub withdrawal_recipient: Felt,
    pub withdrawal_amount: Felt,
    pub intent: Felt,
    pub identity: Vec<Felt>,
    pub account: Felt,
    pub valid_until: u64,
}

impl StatementV5 {
    /// `Poseidon('TMR0_BIND_V5', chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
    /// recipient, amount, intent, identity₉, valid_until)`; never the account (spec §5.2).
    pub fn binding(&self) -> Felt {
        let mut b = vec![short_string("TMR0_BIND_V5").expect("short"), self.chain, self.pool, self.token_out];
        b.extend(&self.root);
        b.extend(&self.nullifiers[0]);
        b.extend(&self.nullifiers[1]);
        b.extend(&self.commitments[0]);
        b.push(self.deliveries[0]);
        b.extend(&self.commitments[1]);
        b.push(self.deliveries[1]);
        b.extend([self.withdrawal_recipient, self.withdrawal_amount, self.intent]);
        b.extend(&self.identity);
        b.push(Felt::from(self.valid_until));
        Poseidon::hash_array(&b)
    }
}

/// `spend::delivery_digest`: `Poseidon('CTRL_DELIVERY_V1', 304, words…)` over ten words, nine
/// below 2^248 and the last below 2^200.
pub fn delivery_digest(words: &[Felt]) -> Result<Felt> {
    ensure!(words.len() == 10, "ciphertext: expected ten words");
    for (i, w) in words.iter().enumerate() {
        ensure!(below(w, if i == 9 { 200 } else { 248 }), "ciphertext: word {i} out of range");
    }
    let mut data = vec![short_string("CTRL_DELIVERY_V1")?, Felt::from(304u64)];
    data.extend_from_slice(words);
    Ok(Poseidon::hash_array(&data))
}

/// One open-note destination (`open_note::OpenDestination`).
#[derive(Debug, Clone)]
pub struct Destination {
    pub note_id: Felt,
    pub token: Felt,
    pub minimum: Felt,
    pub inner: Vec<Felt>,
    pub ciphertext: Vec<Felt>,
}

/// An execution intent's preimage (`open_note::ExecutionIntent`).
#[derive(Debug, Clone)]
pub struct Intent {
    pub kind: u64,
    pub adapter: Felt,
    pub nonce: Felt,
    pub expiry: u64,
    pub calldata: Vec<Felt>,
    pub destinations: Vec<Destination>,
}

impl Intent {
    /// `open_note::hash_intent_of` over the spend's chain, pool, asset and withdrawal (the budget).
    pub fn hash(&self, chain: Felt, pool: Felt, token: Felt, recipient: Felt, amount: Felt) -> Result<Felt> {
        ensure!(self.calldata.len() <= MAX_INTENT_CALLDATA, "intent: calldata too long");
        let n = self.destinations.len();
        ensure!(n > 0 && n <= MAX_DESTINATIONS, "intent: one or two destinations");
        ensure!(self.nonce == Felt::ZERO, "intent: nonzero nonce");
        let selector = match self.kind {
            INVOKE => sn_keccak("privacy_invoke"),
            COMPUTE => sn_keccak("privacy_invoke_with_computation"),
            _ => bail!("intent: unknown kind"),
        };
        let mut data = vec![
            short_string("OPEN_EXEC_V1")?, chain, pool, token, Felt::from(self.kind), self.adapter, self.nonce, recipient, amount,
            Felt::from(self.expiry), selector, Felt::from(self.calldata.len() as u64),
        ];
        data.extend(&self.calldata);
        data.push(Felt::from(n as u64));
        for (i, d) in self.destinations.iter().enumerate() {
            ensure!(d.note_id != Felt::ZERO && d.token != Felt::ZERO && d.minimum != Felt::ZERO, "intent: destination {i}");
            ensure!(d.inner.len() == 9 && d.inner.iter().any(|w| *w != Felt::ZERO), "intent: destination {i} inner");
            ensure!(self.destinations[..i].iter().all(|o| o.note_id != d.note_id), "intent: duplicate note id");
            data.extend([d.note_id, d.token, d.minimum]);
            data.extend(&d.inner);
            data.push(delivery_digest(&d.ciphertext)?);
        }
        Ok(Poseidon::hash_array(&data))
    }
}

/// The job's pool call: `apply_spend(spend, proof)` or `apply_spend_with_invoke(spend, intent,
/// proof)` on pool V3, with the proof span empty (the proof travels in the transaction).
#[derive(Debug, Clone)]
pub struct PoolCall {
    pub entry_point: String,
    pub calldata: Vec<Felt>,
    pub spend: StatementV5,
    pub binding: Felt,
    pub intent: Option<Intent>,
}

/// A cursor over felts that refuses anything malformed.
struct Reader<'a> {
    felts: &'a [Felt],
    at: usize,
}

impl Reader<'_> {
    fn felt(&mut self, what: &str) -> Result<Felt> {
        let f = *self.felts.get(self.at).with_context(|| format!("pool call: {what}: truncated"))?;
        self.at += 1;
        Ok(f)
    }
    fn int(&mut self, what: &str, bits: u32) -> Result<Felt> {
        let f = self.felt(what)?;
        ensure!(below(&f, bits), "pool call: {what}: out of range");
        Ok(f)
    }
    fn small(&mut self, what: &str, max: u64) -> Result<u64> {
        let f = self.felt(what)?;
        let v = to_u64(&f).with_context(|| format!("pool call: {what}: out of range"))?;
        ensure!(v <= max, "pool call: {what}: out of range");
        Ok(v)
    }
    fn span(&mut self, what: &str, len: Option<usize>, max: usize) -> Result<Vec<Felt>> {
        let n = self.small(what, max as u64)? as usize;
        if let Some(want) = len {
            ensure!(n == want, "pool call: {what}: expected {want} felts");
        }
        (0..n).map(|_| self.felt(what)).collect()
    }
    fn words(&mut self, what: &str) -> Result<Vec<Felt>> {
        let w = self.span(what, Some(9), 9)?;
        ensure!(w.iter().all(|x| below(x, 31) && *x != Felt::from((1u64 << 31) - 1)), "pool call: {what}: not canonical M31 words");
        Ok(w)
    }
    fn address(&mut self, what: &str) -> Result<Felt> {
        self.int(what, 251)
    }
}

impl PoolCall {
    /// Parses the calldata of `entry_point` exactly: every length, every range, nothing after.
    pub fn parse(entry_point: &str, calldata: Vec<Felt>) -> Result<PoolCall> {
        ensure!(calldata.len() <= MAX_POOL_CALL_FELTS, "pool call: too long");
        let invoke = match entry_point {
            "apply_spend" => false,
            "apply_spend_with_invoke" => true,
            _ => bail!("pool call: entry point must be apply_spend or apply_spend_with_invoke"),
        };
        let mut r = Reader { felts: &calldata, at: 0 };
        let chain = r.felt("chain")?;
        let pool = r.address("pool")?;
        let token_out = r.address("asset")?;
        let root = r.words("root")?;
        let nfs = r.span("nullifiers", Some(18), 18)?;
        ensure!(nfs.iter().all(|x| below(x, 31) && *x != Felt::from((1u64 << 31) - 1)), "pool call: nullifiers: not canonical");
        ensure!(r.small("outputs", 2)? == 2, "pool call: exactly two outputs");
        let (mut commitments, mut deliveries) = (vec![], vec![]);
        for _ in 0..2 {
            commitments.push(r.words("commitment")?);
            deliveries.push(delivery_digest(&r.span("ciphertext", Some(10), 10)?)?);
        }
        let withdrawal_recipient = r.address("withdrawal recipient")?;
        let withdrawal_amount = r.int("withdrawal amount", 128)?;
        let intent = r.felt("intent")?;
        let identity = r.words("identity")?;
        let valid_until = r.small("valid_until", u64::MAX)?;
        let binding = r.felt("binding")?;
        let intent_preimage = if invoke {
            let kind = r.small("intent kind", u8::MAX as u64)?;
            let adapter = r.address("intent adapter")?;
            let nonce = r.felt("intent nonce")?;
            let expiry = r.small("intent expiry", u64::MAX)?;
            let icalldata = r.span("intent calldata", None, MAX_INTENT_CALLDATA)?;
            let n = r.small("destinations", MAX_DESTINATIONS as u64)? as usize;
            let mut destinations = vec![];
            for _ in 0..n {
                destinations.push(Destination {
                    note_id: r.felt("note id")?,
                    token: r.address("destination token")?,
                    minimum: r.int("destination minimum", 128)?,
                    inner: r.words("destination inner")?,
                    ciphertext: r.span("destination ciphertext", Some(10), 10)?,
                });
            }
            Some(Intent { kind, adapter, nonce, expiry, calldata: icalldata, destinations })
        } else {
            None
        };
        ensure!(r.small("proof", 0)? == 0, "pool call: the proof span must be empty");
        ensure!(r.at == calldata.len(), "pool call: trailing felts");
        let [n0, n1] = [nfs[..9].to_vec(), nfs[9..].to_vec()];
        let spend = StatementV5 {
            chain, pool, token_out, root, nullifiers: [n0, n1],
            commitments: [commitments[0].clone(), commitments[1].clone()], deliveries: [deliveries[0], deliveries[1]],
            withdrawal_recipient, withdrawal_amount, intent, identity, account: Felt::ZERO, valid_until,
        };
        Ok(PoolCall { entry_point: entry_point.to_string(), calldata, spend, binding, intent: intent_preimage })
    }

    /// The pool call settles exactly `statement`, whose binding the bridge returned as
    /// `bridge_binding` (spec §9 step 7).
    pub fn matches(&self, statement: &StatementV5, bridge_binding: Felt) -> Result<()> {
        let s = &self.spend;
        let st = StatementV5 { account: Felt::ZERO, ..statement.clone() };
        ensure!(*s == st, "pool call: the spend does not match the statement");
        let binding = statement.binding();
        ensure!(binding == bridge_binding, "pool call: the statement's binding is not the bridge's");
        ensure!(self.binding == binding, "pool call: the spend's binding field is not the statement's binding");
        match &self.intent {
            None => ensure!(s.intent == Felt::ZERO && s.identity.iter().all(|w| *w == Felt::ZERO), "pool call: an intent or identity needs apply_spend_with_invoke"),
            Some(i) => {
                ensure!(s.intent != Felt::ZERO, "pool call: an invoke with a zero intent");
                let h = i.hash(s.chain, s.pool, s.token_out, s.withdrawal_recipient, s.withdrawal_amount)?;
                ensure!(h == s.intent, "pool call: the intent preimage does not hash to the statement's intent");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::felt;
    use serde_json::Value;

    /// `Intent::hash` against `bench/m31-pool/open_note.py`'s `hash_intent` (the Python reference,
    /// computed independently) for INVOKE and COMPUTE with two destinations (AB-SM8).
    #[test]
    fn intent_hash_matches_the_python_reference() {
        let d = |k: u64| Destination {
            note_id: Felt::from(77 + k), token: Felt::from(0x7e57b3a2 + k), minimum: Felt::from(1 + k),
            inner: (1..10u64).map(|x| Felt::from(x + 100 * k)).collect(), ciphertext: (1..11u64).map(|x| Felt::from(x + 1000 * k)).collect(),
        };
        for (kind, want) in [
            (INVOKE, "0x1441baf8db1a9ffd2f9aa835114246c4e528fc8ba84af917c165838d41ac875"),
            (COMPUTE, "0x7a5d3fd616f1fa9cef11e289d9848606924bdf3abb20f17633188dc2b952163"),
        ] {
            let i = Intent { kind, adapter: Felt::from(0xadau64), nonce: Felt::ZERO, expiry: 7000, calldata: vec![Felt::from(5u64), Felt::from(6u64)], destinations: vec![d(0), d(1)] };
            let h = i.hash(short_string("SN_SEPOLIA").unwrap(), Felt::from(0x7e57b301u64), Felt::from(0x7e57b3a1u64), Felt::from(0xb0bu64), Felt::from(400u64)).unwrap();
            assert_eq!(h, felt(want).unwrap(), "kind {kind}");
        }
    }

    const KAT: &str = include_str!("../../../bench/m31-private-wrapper/client-port/cairo-r5/kat/kat.json");

    fn fv(v: &Value) -> Felt {
        let s = v.as_str().unwrap();
        if let Some(h) = s.strip_prefix("0x") {
            felt(&format!("0x{h}")).unwrap()
        } else {
            Felt::from_dec_str(s).unwrap()
        }
    }
    fn words(v: &Value) -> Vec<Felt> {
        v.as_array().unwrap().iter().map(fv).collect()
    }

    fn statement(s: &Value, account: Felt) -> StatementV5 {
        StatementV5 {
            chain: fv(&s["chain"]), pool: fv(&s["pool"]), token_out: fv(&s["token_out"]), root: words(&s["root"]),
            nullifiers: [words(&s["nullifiers"][0]), words(&s["nullifiers"][1])],
            commitments: [words(&s["commitments"][0]), words(&s["commitments"][1])],
            deliveries: [fv(&s["deliveries"][0]), fv(&s["deliveries"][1])],
            withdrawal_recipient: fv(&s["withdrawal_recipient"]), withdrawal_amount: fv(&s["withdrawal_amount"]),
            intent: fv(&s["intent"]), identity: words(&s["identity"]), account,
            valid_until: to_u64(&fv(&s["valid_until"])).unwrap(),
        }
    }

    /// The binding equals starknet.js's known answers, and never depends on the account.
    #[test]
    fn binding_matches_starknet_js() {
        let kat: Value = serde_json::from_str(KAT).unwrap();
        for b in kat["bindings"].as_array().unwrap() {
            assert_eq!(statement(&b["statement"], Felt::ZERO).binding(), fv(&b["binding"]), "{}", b["name"]);
            assert_eq!(statement(&b["statement"], Felt::from(0x123u64)).binding(), fv(&b["binding"]), "the account is not bound");
        }
    }

    fn span(xs: &[Felt]) -> Vec<Felt> {
        [vec![Felt::from(xs.len() as u64)], xs.to_vec()].concat()
    }

    /// A statement and the `apply_spend` calldata that settles it.
    fn fixture() -> (StatementV5, Vec<Felt>) {
        let w = |s: u64| (0..9).map(|k| Felt::from(s + k)).collect::<Vec<_>>();
        let ct = |s: u64| (0..10).map(|k| Felt::from(s * 1000 + k + 1)).collect::<Vec<_>>();
        let (ct0, ct1) = (ct(1), ct(2));
        let st = StatementV5 {
            chain: short_string("SN_SEPOLIA").unwrap(), pool: Felt::from(0x7e57b301u64), token_out: Felt::from(0x7e57b3a1u64),
            root: w(1), nullifiers: [w(10), w(20)], commitments: [w(30), w(40)],
            deliveries: [delivery_digest(&ct0).unwrap(), delivery_digest(&ct1).unwrap()],
            withdrawal_recipient: Felt::from(0xb0bu64), withdrawal_amount: Felt::from(400u64), intent: Felt::ZERO,
            identity: vec![Felt::ZERO; 9], account: Felt::ZERO, valid_until: 6500,
        };
        let mut c = vec![st.chain, st.pool, st.token_out];
        c.extend(span(&st.root));
        c.extend(span(&[st.nullifiers[0].clone(), st.nullifiers[1].clone()].concat()));
        c.push(Felt::TWO);
        c.extend(span(&st.commitments[0]));
        c.extend(span(&ct0));
        c.extend(span(&st.commitments[1]));
        c.extend(span(&ct1));
        c.extend([st.withdrawal_recipient, st.withdrawal_amount, st.intent]);
        c.extend(span(&st.identity));
        c.push(Felt::from(st.valid_until));
        c.push(st.binding());
        c.push(Felt::ZERO);
        (st, c)
    }

    #[test]
    fn pool_call_matches_its_statement() {
        let (st, c) = fixture();
        let call = PoolCall::parse("apply_spend", c.clone()).unwrap();
        call.matches(&st, st.binding()).unwrap();
        // The bridge's binding must agree.
        assert!(call.matches(&st, st.binding() + Felt::ONE).is_err());
        // Every field of the spend is matched (the account never is: it is not in the calldata).
        let binding_at = c.len() - 2;
        for i in 0..binding_at {
            let mut bad = c.clone();
            bad[i] += Felt::ONE;
            let ok = PoolCall::parse("apply_spend", bad).and_then(|p| p.matches(&st, st.binding()));
            assert!(ok.is_err(), "felt {i} altered and still accepted");
        }
        let mut bad = c.clone();
        bad[binding_at] += Felt::ONE;
        assert!(PoolCall::parse("apply_spend", bad).unwrap().matches(&st, st.binding()).is_err(), "binding field");
    }

    #[test]
    fn pool_call_refuses_malformed() {
        let (_, c) = fixture();
        assert!(PoolCall::parse("apply_spend_with_invoke", c.clone()).is_err(), "no intent preimage");
        assert!(PoolCall::parse("deposit", c.clone()).is_err(), "entry point");
        let mut trailing = c.clone();
        trailing.push(Felt::ZERO);
        assert!(PoolCall::parse("apply_spend", trailing).is_err(), "trailing felts");
        assert!(PoolCall::parse("apply_spend", c[..c.len() - 1].to_vec()).is_err(), "truncated");
        let mut proof = c.clone();
        *proof.last_mut().unwrap() = Felt::ONE;
        assert!(PoolCall::parse("apply_spend", proof).is_err(), "a proof span");
        let mut word = c.clone();
        word[4] = Felt::from((1u64 << 31) - 1);
        assert!(PoolCall::parse("apply_spend", word).is_err(), "a non-canonical root word");
        let mut big = c.clone();
        big[1] = two_pow(251);
        assert!(PoolCall::parse("apply_spend", big).is_err(), "pool at 2^251");
    }

    /// An invoke's intent preimage must hash to the statement's intent.
    #[test]
    fn invoke_intent_is_checked() {
        let (mut st, c) = fixture();
        let intent = Intent {
            kind: INVOKE, adapter: Felt::from(0xadau64), nonce: Felt::ZERO, expiry: 7000, calldata: vec![Felt::from(5u64)],
            destinations: vec![Destination {
                note_id: Felt::from(77u64), token: Felt::from(0x7e57b3a2u64), minimum: Felt::ONE,
                inner: (1..10u64).map(Felt::from).collect(), ciphertext: (1..11u64).map(Felt::from).collect(),
            }],
        };
        st.intent = intent.hash(st.chain, st.pool, st.token_out, st.withdrawal_recipient, st.withdrawal_amount).unwrap();
        let mut call = c[..c.len() - 3].to_vec(); // …, identity; then valid_until, binding, proof
        let intent_at = 3 + 10 + 19 + 1 + 2 * (10 + 11) + 2;
        call[intent_at] = st.intent;
        call.push(Felt::from(st.valid_until));
        call.push(st.binding());
        call.extend([Felt::ZERO, intent.adapter, Felt::ZERO, Felt::from(intent.expiry)]);
        call.extend(span(&intent.calldata));
        call.push(Felt::ONE);
        let d = &intent.destinations[0];
        call.extend([d.note_id, d.token, d.minimum]);
        call.extend(span(&d.inner));
        call.extend(span(&d.ciphertext));
        call.push(Felt::ZERO);
        let parsed = PoolCall::parse("apply_spend_with_invoke", call.clone()).unwrap();
        parsed.matches(&st, st.binding()).unwrap();
        // Another adapter in the preimage no longer hashes to the statement's intent.
        let adapter_at = call.iter().position(|x| *x == intent.adapter).unwrap();
        let mut bad = call.clone();
        bad[adapter_at] += Felt::ONE;
        assert!(PoolCall::parse("apply_spend_with_invoke", bad).unwrap().matches(&st, st.binding()).is_err());
        // A plain apply_spend of a statement with an intent is refused.
        assert!(PoolCall::parse("apply_spend", c).unwrap().matches(&st, st.binding()).is_err());
    }
}
