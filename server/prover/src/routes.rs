//! Routing adapters (`docs/pool-v3-spec.md` §6, §9.2, §9.5): decoding their views, the pins a
//! routed relation checks at admission and at job start, and its own route's pending changes.
//!
//! A `Route` is eight felts in the adapter's Serde order: `statement, statement_class,
//! account_tag, os_program, proof_version, proof_variant, output_version, max_proof_age` (the
//! known-answer vector `route_serde_order` in `bench/m31-pool/cairo/src/tests/test_routing_adapter.cairo`).
//! `Option<Route>` is `0` then the route, or `1`.
use anyhow::{bail, Context, Result};
use starknet_types_core::felt::Felt;

use crate::config::{Config, RelationConfig, RoutePin};
use crate::pipeline::proposal_live;
use crate::rpc::{felt, hex, short_string, Rpc};

pub const ROUTE_FELTS: usize = 8;

/// A route's eight felts, in the adapter's Serde order.
pub fn route_felts(r: &RoutePin) -> Result<[Felt; ROUTE_FELTS]> {
    Ok([
        felt(&r.statement)?,
        felt(&r.statement_class)?,
        short_string(&r.account_tag)?,
        felt(&r.os_program)?,
        short_string(&r.proof_version)?,
        short_string(&r.proof_variant)?,
        short_string(&r.output_version)?,
        Felt::from(r.max_proof_age),
    ])
}

fn take<'a>(v: &'a [Felt], at: &mut usize, n: usize, what: &str) -> Result<&'a [Felt]> {
    let s = v.get(*at..*at + n).with_context(|| format!("{what}: truncated"))?;
    *at += n;
    Ok(s)
}

fn small(x: &Felt, what: &str) -> Result<u64> {
    crate::v5::to_u64(x).with_context(|| format!("{what}: not a small integer"))
}

fn option_route(v: &[Felt], at: &mut usize, what: &str) -> Result<Option<[Felt; ROUTE_FELTS]>> {
    match small(&take(v, at, 1, what)?[0], what)? {
        0 => Ok(Some(take(v, at, ROUTE_FELTS, what)?.try_into().unwrap())),
        1 => Ok(None),
        _ => bail!("{what}: bad Option tag"),
    }
}

/// `get_routes()`: `[n, route₀ … routeₙ₋₁]`.
pub fn decode_routes(v: &[Felt]) -> Result<Vec<[Felt; ROUTE_FELTS]>> {
    let mut at = 0;
    let n = small(&take(v, &mut at, 1, "get_routes")?[0], "get_routes")? as usize;
    let routes = (0..n).map(|_| Ok(take(v, &mut at, ROUTE_FELTS, "get_routes")?.try_into().unwrap())).collect::<Result<Vec<_>>>()?;
    if at != v.len() {
        bail!("get_routes: trailing felts");
    }
    Ok(routes)
}

/// `get_route(statement)`: an `Option<Route>`.
pub fn decode_route(v: &[Felt]) -> Result<Option<[Felt; ROUTE_FELTS]>> {
    let mut at = 0;
    let r = option_route(v, &mut at, "get_route")?;
    if at != v.len() {
        bail!("get_route: trailing felts");
    }
    Ok(r)
}

/// One pending route change: an addition (`Some`) or a removal (`None`) of `statement`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteProposal {
    pub statement: Felt,
    pub route: Option<[Felt; ROUTE_FELTS]>,
    pub eta: u64,
}

/// `get_route_proposals()`: `[n, (statement, Option<Route>, eta)…]`.
pub fn decode_proposals(v: &[Felt]) -> Result<Vec<RouteProposal>> {
    let mut at = 0;
    let n = small(&take(v, &mut at, 1, "get_route_proposals")?[0], "get_route_proposals")? as usize;
    let mut out = vec![];
    for _ in 0..n {
        let statement = take(v, &mut at, 1, "get_route_proposals")?[0];
        let route = option_route(v, &mut at, "get_route_proposals")?;
        let eta = small(&take(v, &mut at, 1, "get_route_proposals")?[0], "get_route_proposals eta")?;
        out.push(RouteProposal { statement, route, eta });
    }
    if at != v.len() {
        bail!("get_route_proposals: trailing felts");
    }
    Ok(out)
}

/// The pins a routed relation checks while its adapter is the pool's verifier (§9.2, §10.2):
/// the adapter's class and pool, its kind, a route set equal to a pinned state, the own route
/// active and equal to its pin in all eight fields, and each active route's class on chain.
pub async fn check_pins(rpc: &Rpc, cfg: &Config, rel: &RelationConfig, kind: Felt) -> Result<()> {
    let adapter = &rel.adapter;
    let class = rpc.class_hash_at(adapter).await?;
    if Some(class) != rel.adapter_class.as_deref().map(felt).transpose()? {
        bail!("{}: the routing adapter's class is {}, not the pinned one", rel.name, hex(&class));
    }
    if rpc.call(adapter, "get_pool", &[]).await?.first() != Some(&felt(&cfg.network.pool)?) {
        bail!("{}: the routing adapter serves another pool", rel.name);
    }
    if rpc.call(adapter, "get_kind", &[]).await?.first() != Some(&kind) {
        bail!("{}: the routing adapter is for another verifier kind", rel.name);
    }
    let routes = decode_routes(&rpc.call(adapter, "get_routes", &[]).await?)?;
    let mut keys: Vec<Felt> = routes.iter().map(|r| r[0]).collect();
    keys.sort();
    if !rel.pinned_states()?.contains(&keys) {
        bail!("{}: the adapter's route set is not a pinned state", rel.name);
    }
    for r in &routes {
        let pin = rel.routes.iter().find(|p| felt(&p.statement).ok() == Some(r[0])).context("a route this release does not know")?;
        if route_felts(pin)? != *r {
            bail!("{}: route {} differs from its pin", rel.name, hex(&r[0]));
        }
        if rpc.class_hash_at(&hex(&r[0])).await? != r[1] {
            bail!("{}: route {}'s statement class changed", rel.name, hex(&r[0]));
        }
    }
    let own = rel.own_route().context("the own route")?;
    let got = decode_route(&rpc.call(adapter, "get_route", &[felt(&own.statement)?]).await?)?;
    if got != Some(route_felts(own)?) {
        bail!("{}: the own route is not active as pinned", rel.name);
    }
    Ok(())
}

/// A change to the own route is due (§9.5): refused from `pending_margin` before its `eta` until
/// `eta + T`, unless applied, cancelled or lapsed. A route under another key never stops the
/// server.
pub async fn own_route_change_due(rpc: &Rpc, cfg: &Config, rel: &RelationConfig) -> Result<()> {
    let t = cfg.network.parameters.context("pool V3 parameters not read")?.timelock;
    let own = felt(&rel.own_route().context("the own route")?.statement)?;
    let proposals = decode_proposals(&rpc.call(&rel.adapter, "get_route_proposals", &[]).await?)?;
    let now = rpc.latest_timestamp().await?;
    for p in proposals.iter().filter(|p| p.statement == own) {
        if proposal_live(p.eta, now, cfg.pending_margin(), t) {
            bail!("a change of {}'s own route can apply between {} and {}; retry after it is applied, cancelled or lapsed",
                  rel.name, p.eta, p.eta.saturating_add(t));
        }
    }
    Ok(())
}

/// A relation whose adapter is not the pool's current verifier for its kind is dormant (§9.5):
/// the server keeps it configured and refuses its jobs until the pool switches to it.
#[derive(Debug)]
pub struct Dormant(pub String);

impl std::fmt::Display for Dormant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is dormant: the pool's verifier for its kind is another adapter; retry later", self.0)
    }
}

impl std::error::Error for Dormant {}

pub fn dormant(rel: &RelationConfig) -> anyhow::Error {
    anyhow::Error::new(Dormant(rel.name.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> RoutePin {
        RoutePin {
            statement: "0x5a7e".into(), statement_class: "0xc1a5".into(), account_tag: "TMPZR0_PAYMENT_V6".into(),
            os_program: "0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1".into(), proof_version: "PROOF2".into(),
            proof_variant: "VIRTUAL_SNOS".into(), output_version: "VIRTUAL_SNOS0".into(), max_proof_age: 1024,
        }
    }

    /// The Serde order the adapter's `route_serde_order` test fixes.
    #[test]
    fn route_serde_order() {
        let f = route_felts(&pin()).unwrap();
        assert_eq!(f[0], Felt::from(0x5a7eu64));
        assert_eq!(f[1], Felt::from(0xc1a5u64));
        assert_eq!(f[2], short_string("TMPZR0_PAYMENT_V6").unwrap());
        assert_eq!(f[3], felt("0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1").unwrap());
        assert_eq!(f[4..7], [short_string("PROOF2").unwrap(), short_string("VIRTUAL_SNOS").unwrap(), short_string("VIRTUAL_SNOS0").unwrap()]);
        assert_eq!(f[7], Felt::from(1024u64));
    }

    fn pin_of(v: &serde_json::Value) -> RoutePin {
        let text = |k: &str| v[k].as_str().unwrap().to_string();
        RoutePin {
            statement: text("statement"), statement_class: text("statement_class"), account_tag: text("account_tag"),
            os_program: text("os_program"), proof_version: text("proof_version"), proof_variant: text("proof_variant"),
            output_version: text("output_version"), max_proof_age: v["max_proof_age"].as_u64().unwrap(),
        }
    }
    fn felts_of(v: &serde_json::Value) -> Vec<Felt> {
        v.as_array().unwrap().iter().map(|x| felt(x.as_str().unwrap()).unwrap()).collect()
    }

    /// The shared encoding vectors (`sdk/vectors/routing.json`, pinned by the adapter's
    /// `routing_vectors_match_serde`): a route's felts, and both views decoded.
    #[test]
    fn shared_routing_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../../sdk/vectors/routing.json")).unwrap();
        let (a, b) = (pin_of(&v["routes"]["r0_v6"]), pin_of(&v["routes"]["p1_v1"]));
        let (fa, fb) = (route_felts(&a).unwrap(), route_felts(&b).unwrap());
        assert_eq!(fa.to_vec(), felts_of(&v["routes"]["r0_v6"]["felts"]));
        assert_eq!(fb.to_vec(), felts_of(&v["routes"]["p1_v1"]["felts"]));
        assert_eq!(decode_route(&felts_of(&v["some_r0_v6"])).unwrap(), Some(fa));
        assert_eq!(decode_route(&felts_of(&v["none"])).unwrap(), None);
        assert_eq!(decode_routes(&felts_of(&v["get_routes"]["felts"])).unwrap(), vec![fa, fb]);
        let props = decode_proposals(&felts_of(&v["get_route_proposals"]["felts"])).unwrap();
        let want = v["get_route_proposals"]["proposals"].as_array().unwrap();
        assert_eq!(props.len(), want.len());
        for (p, w) in props.iter().zip(want) {
            assert_eq!(p.statement, felt(w["statement"].as_str().unwrap()).unwrap());
            assert_eq!(p.eta, w["eta"].as_u64().unwrap());
            assert_eq!(p.route, w["route"].as_str().map(|k| route_felts(&pin_of(&v["routes"][k])).unwrap()));
        }
    }

    #[test]
    fn decodes_views() {
        let r = route_felts(&pin()).unwrap();
        let routes = [vec![Felt::TWO], r.to_vec(), r.to_vec()].concat();
        assert_eq!(decode_routes(&routes).unwrap(), vec![r, r]);
        assert!(decode_routes(&routes[..10]).is_err(), "truncated");
        assert!(decode_routes(&[routes.clone(), vec![Felt::ONE]].concat()).is_err(), "trailing");
        assert_eq!(decode_route(&[vec![Felt::ZERO], r.to_vec()].concat()).unwrap(), Some(r));
        assert_eq!(decode_route(&[Felt::ONE]).unwrap(), None);
        assert!(decode_route(&[Felt::TWO]).is_err());
        // Two proposals: an addition, then a removal.
        let props = [vec![Felt::TWO, Felt::from(7u64), Felt::ZERO], r.to_vec(), vec![Felt::from(100u64), Felt::from(8u64), Felt::ONE, Felt::from(200u64)]].concat();
        assert_eq!(decode_proposals(&props).unwrap(), vec![
            RouteProposal { statement: Felt::from(7u64), route: Some(r), eta: 100 },
            RouteProposal { statement: Felt::from(8u64), route: None, eta: 200 },
        ]);
        assert_eq!(decode_proposals(&[Felt::ZERO]).unwrap(), vec![]);
    }
}
