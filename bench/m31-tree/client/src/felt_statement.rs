//! Public residual RTN_NOTE_V1 hash workload. The original felt binding root is independent
//! of the experimental M31 root; this module does not define a migrated payment ABI.
use anyhow::{Result, ensure};
use cairo_air::relations::{CommonLookupElements, MEMORY_ID_TO_BIG_RELATION_ID};
use serde::{Deserialize, Serialize};
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use std::collections::{BTreeMap, BTreeSet};
use stwo::core::fields::{m31::M31, qm31::QM31};
use stwo_cairo_common::{memory::LARGE_MEMORY_VALUE_ID_BASE, prover_types::cpu::Felt252};
use stwo_constraint_framework::Relation;
pub fn felt(s: &str) -> Result<Felt> {
    let f = Felt::from_hex(s)?;
    ensure!(format!("{f:#x}") == s, "noncanonical felt252");
    Ok(f)
}
pub fn hex(f: Felt) -> String {
    format!("{f:#x}")
}
fn label(s: &str) -> Felt {
    Felt::from_bytes_be_slice(s.as_bytes())
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Permutation {
    pub input: [String; 3],
    pub output: [String; 3],
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Call {
    pub name: String,
    pub values: Vec<String>,
    pub result: String,
    pub permutations: Vec<Permutation>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Input {
    pub sk: String,
    pub rho: String,
    pub amount: u128,
    pub index: u32,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Output {
    pub receiver: String,
    pub rho: String,
    pub amount: u128,
    pub delivery: String,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Workload {
    pub chain: String,
    pub pool: String,
    pub token: String,
    pub binding_root_independent: String,
    pub version: String,
    pub inputs: [Input; 2],
    pub outputs: [Output; 2],
    pub calls: Vec<Call>,
}

pub type Request = ([M31; 3], [M31; 3]);
pub struct PublicData {
    pub values: Vec<Felt>,
    pub requests: Vec<Request>,
    pub rows: Vec<Request>,
    pub unique: Vec<(Request, u32)>,
}

fn build_call(name: &str, values: Vec<Felt>) -> Call {
    let mut state = [Felt::ZERO; 3];
    let mut permutations = Vec::new();
    let mut i = 0;
    let apply = |s: &mut [Felt; 3], permutations: &mut Vec<Permutation>| {
        let input = *s;
        Poseidon::hades_permutation(s);
        permutations.push(Permutation {
            input: input.map(hex),
            output: s.map(hex),
        });
    };
    while i + 2 <= values.len() {
        state[0] += values[i];
        state[1] += values[i + 1];
        apply(&mut state, &mut permutations);
        i += 2;
    }
    if i < values.len() {
        state[0] += values[i];
        state[1] += Felt::ONE;
    } else {
        state[0] += Felt::ONE;
    }
    apply(&mut state, &mut permutations);
    assert_eq!(state[0], Poseidon::hash_array(&values));
    Call {
        name: name.into(),
        values: values.into_iter().map(hex).collect(),
        result: hex(state[0]),
        permutations,
    }
}
fn check_call(call: &Call, name: &str, values: Vec<Felt>) -> Result<Felt> {
    ensure!(
        call.name == name && call.values == values.iter().copied().map(hex).collect::<Vec<_>>(),
        "residual call binding"
    );
    let mut state = [Felt::ZERO; 3];
    let mut i = 0;
    let mut requests = call.permutations.iter();
    let apply =
        |s: &mut [Felt; 3], requests: &mut std::slice::Iter<'_, Permutation>| -> Result<()> {
            let r = requests
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing Hades permutation"))?;
            let input = [felt(&r.input[0])?, felt(&r.input[1])?, felt(&r.input[2])?];
            ensure!(input == *s, "felt hash_span absorption/padding");
            *s = [
                felt(&r.output[0])?,
                felt(&r.output[1])?,
                felt(&r.output[2])?,
            ];
            Ok(())
        };
    while i + 2 <= values.len() {
        state[0] += values[i];
        state[1] += values[i + 1];
        apply(&mut state, &mut requests)?;
        i += 2;
    }
    if i < values.len() {
        state[0] += values[i];
        state[1] += Felt::ONE;
    } else {
        state[0] += Felt::ONE;
    }
    apply(&mut state, &mut requests)?;
    ensure!(requests.next().is_none(), "extra Hades permutation");
    ensure!(felt(&call.result)? == state[0], "felt hash result");
    Ok(state[0])
}
impl Workload {
    pub fn synthetic() -> Self {
        Self {
            chain: "0x534e5f5345504f4c4941".into(),
            pool: "0x456".into(),
            token: "0x789".into(),
            binding_root_independent: "0x123456789abcdef".into(),
            version: hex(label("TEMPLAR_RETURN_POC1")),
            inputs: [
                Input {
                    sk: "0x101".into(),
                    rho: "0x201".into(),
                    amount: 31,
                    index: 0x13579bdf,
                },
                Input {
                    sk: "0x102".into(),
                    rho: "0x202".into(),
                    amount: 41,
                    index: 0xeca86420,
                },
            ],
            outputs: [
                Output {
                    receiver: "0x301".into(),
                    rho: "0x401".into(),
                    amount: 33,
                    delivery: "0x501".into(),
                },
                Output {
                    receiver: "0x302".into(),
                    rho: "0x402".into(),
                    amount: 39,
                    delivery: "0x502".into(),
                },
            ],
            calls: vec![],
        }
    }
    fn walk(&self, mut h: impl FnMut(&str, Vec<Felt>) -> Result<Felt>) -> Result<[Felt; 2]> {
        let chain = felt(&self.chain)?;
        let pool = felt(&self.pool)?;
        let token = felt(&self.token)?;
        let root = felt(&self.binding_root_independent)?;
        let version = felt(&self.version)?;
        ensure!(
            chain != Felt::ZERO && pool != Felt::ZERO && token != Felt::ZERO,
            "zero residual context"
        );
        ensure!(
            version == label("TEMPLAR_RETURN_POC1"),
            "residual reference version"
        );
        let mut cms = [Felt::ZERO; 2];
        let mut nfs = vec![];
        let mut outs = vec![];
        for (i, input) in self.inputs.iter().enumerate() {
            let sk = felt(&input.sk)?;
            let rho = felt(&input.rho)?;
            ensure!(
                sk != Felt::ZERO && rho != Felt::ZERO && input.amount > 0,
                "invalid residual input"
            );
            let ak = h(&format!("input{i}.auth"), vec![label("RTN_AUTH_V1"), sk])?;
            let nk = h(&format!("input{i}.nk"), vec![label("RTN_NK_V1"), sk])?;
            let receiver = h(
                &format!("input{i}.owner"),
                vec![label("RTN_OWNER_V1"), ak, nk],
            )?;
            let inner = h(
                &format!("input{i}.inner"),
                vec![label("RTN_INNER_V1"), receiver, rho],
            )?;
            let cm = h(
                &format!("input{i}.commitment"),
                vec![
                    label("RTN_NOTE_V1"),
                    chain,
                    pool,
                    token,
                    Felt::from(input.amount),
                    Felt::ZERO,
                    Felt::ZERO,
                    inner,
                ],
            )?;
            cms[i] = cm;
            nfs.push(h(
                &format!("input{i}.nullifier"),
                vec![label("RTN_NF_V1"), nk, cm, Felt::from(input.index)],
            )?);
        }
        for (i, output) in self.outputs.iter().enumerate() {
            let receiver = felt(&output.receiver)?;
            let rho = felt(&output.rho)?;
            ensure!(
                receiver != Felt::ZERO && rho != Felt::ZERO && output.amount > 0,
                "invalid residual output"
            );
            let inner = h(
                &format!("output{i}.inner"),
                vec![label("RTN_INNER_V1"), receiver, rho],
            )?;
            let cm = h(
                &format!("output{i}.commitment"),
                vec![
                    label("RTN_NOTE_V1"),
                    chain,
                    pool,
                    token,
                    Felt::from(output.amount),
                    Felt::ZERO,
                    Felt::ZERO,
                    inner,
                ],
            )?;
            outs.extend([cm, felt(&output.delivery)?]);
        }
        // Exact fixed4/4/2 RTN public binding layout, ctrl/deadline/nonce/transition/intent=0.
        let mut binding = vec![
            label("RTN_BIND_V1"),
            version,
            chain,
            pool,
            root,
            token,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::from(2u32),
        ];
        binding.extend(nfs);
        binding.extend([Felt::ZERO; 2]);
        binding.push(Felt::from(2u32));
        binding.extend(outs);
        binding.extend([Felt::ZERO; 4]);
        binding.push(Felt::ZERO);
        binding.extend([Felt::ZERO; 4]);
        ensure!(binding.len() == 30, "residual binding shape");
        h("binding", binding)?;
        Ok(cms)
    }
    pub fn regenerate(&self) -> Result<Self> {
        let mut out = self.clone();
        let mut calls = vec![];
        self.walk(|name, values| {
            let call = build_call(name, values);
            let r = felt(&call.result)?;
            calls.push(call);
            Ok(r)
        })?;
        out.calls = calls;
        Ok(out)
    }
    pub fn validate(&self) -> Result<(PublicData, [Felt; 2])> {
        let mut cursor = 0;
        let cms = self.walk(|name, values| {
            let call = self
                .calls
                .get(cursor)
                .ok_or_else(|| anyhow::anyhow!("missing residual call"))?;
            cursor += 1;
            check_call(call, name, values)
        })?;
        ensure!(
            cursor == 17 && self.calls.len() == 17,
            "residual call count"
        );
        let permutations: Vec<_> = self.calls.iter().flat_map(|c| &c.permutations).collect();
        ensure!(permutations.len() == 62, "residual permutation count");
        let mut all = vec![];
        for p in permutations {
            all.push((
                [felt(&p.input[0])?, felt(&p.input[1])?, felt(&p.input[2])?],
                [
                    felt(&p.output[0])?,
                    felt(&p.output[1])?,
                    felt(&p.output[2])?,
                ],
            ));
        }
        let values = all
            .iter()
            .flat_map(|(a, b)| a.iter().chain(b))
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let ids = values
            .iter()
            .enumerate()
            .map(|(i, &v)| (v, M31::from(LARGE_MEMORY_VALUE_ID_BASE + i as u32)))
            .collect::<BTreeMap<_, _>>();
        let requests = all
            .into_iter()
            .map(|(a, b)| (a.map(|v| ids[&v]), b.map(|v| ids[&v])))
            .collect::<Vec<_>>();
        let (unique, rows) = derive_rows(&requests)?;
        Ok((
            PublicData {
                values,
                requests,
                rows,
                unique,
            },
            cms,
        ))
    }
}
pub fn derive_rows(requests: &[Request]) -> Result<(Vec<(Request, u32)>, Vec<Request>)> {
    ensure!(
        !requests.is_empty() && requests.len() <= 128,
        "felt request bound"
    );
    let mut map = BTreeMap::new();
    for &(a, b) in requests {
        let (old, n) = map.entry(a).or_insert((b, 0u32));
        ensure!(*old == b, "conflicting felt permutation outputs");
        *n += 1;
    }
    let unique = map
        .into_iter()
        .map(|(a, (b, n))| ((a, b), n))
        .collect::<Vec<_>>();
    let mut rows = unique.iter().map(|(r, _)| *r).collect::<Vec<_>>();
    rows.resize(rows.len().next_power_of_two().max(16), rows[0]);
    Ok((unique, rows))
}
impl PublicData {
    pub fn aggregator_log_size(&self) -> u32 {
        self.rows.len().ilog2()
    }
    pub fn boundary(&self, lookup: &CommonLookupElements) -> QM31 {
        let mut sum = QM31::from(0);
        for (a, b) in &self.requests {
            let tuple = [M31::from(1551892206), a[0], a[1], a[2], b[0], b[1], b[2]];
            let den: QM31 = lookup.combine(&tuple);
            sum += QM31::from(1) / den;
        }
        for (a, b) in &self.rows {
            for id in a.iter().chain(b) {
                let value = self.values[(id.0 - LARGE_MEMORY_VALUE_ID_BASE) as usize];
                let mut tuple = vec![MEMORY_ID_TO_BIG_RELATION_ID, *id];
                tuple.extend(Felt252::from(value).get_limbs());
                let den: QM31 = lookup.combine(&tuple);
                sum -= QM31::from(1) / den;
            }
        }
        sum
    }
}
