//! Oblivious HTTP (RFC 9458, spec §2): a client going through an OHTTP relay hides its address from
//! the server, and the relay sees no content. Built from upstream's gateway primitives
//! (`tower_ohttp`): `GET /ohttp-keys` returns the key configuration; a `message/ohttp-req` request
//! is decapsulated, rebuilt, run through the same routes with the relay's address and an [`Ohttp`]
//! marker (so rate limits apply per relay), and its response encapsulated. Unlike upstream's
//! `OhttpLayer`, the rebuilt request keeps the connection information the rate limiter needs.
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, Limited};
use tower_ohttp::bhttp_codec::{encapsulate_response, rebuild_request};
use tower_ohttp::{OhttpError, OhttpGateway};

/// Marks a request that arrived inside an OHTTP envelope.
#[derive(Clone, Copy)]
pub struct Ohttp;

pub struct OhttpState {
    pub gateway: Arc<OhttpGateway>,
    pub body_limit: usize,
}

const KEYS_PATH: &str = "/ohttp-keys";
const REQUEST_TYPE: &str = "message/ohttp-req";

pub async fn middleware(State(state): State<Arc<OhttpState>>, request: Request, next: Next) -> Response {
    if request.method() == Method::GET && request.uri().path() == KEYS_PATH {
        return (
            [(header::CONTENT_TYPE, "application/ohttp-keys"), (header::CACHE_CONTROL, "public, max-age=3600")],
            state.gateway.encoded_config().to_vec(),
        )
            .into_response();
    }
    let is_ohttp = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.eq_ignore_ascii_case(REQUEST_TYPE));
    if !is_ohttp {
        return next.run(request).await;
    }
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().copied();
    let bytes = match Limited::new(request.into_body(), state.body_limit).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return plain(OhttpError::BodyTooLarge),
    };
    let Ok((bhttp_bytes, server_response)) = state.gateway.server().decapsulate(&bytes) else {
        return plain(OhttpError::DecapsulationFailed);
    };
    // After decapsulation every error is itself encapsulated (RFC 9458 §5.2).
    let inner: Response = match bhttp::Message::read_bhttp(&mut Cursor::new(&bhttp_bytes))
        .map_err(|_| OhttpError::InvalidFormat("Invalid Binary HTTP message"))
        .and_then(|m| rebuild_request(&m))
    {
        Ok(rebuilt) => {
            let mut rebuilt = rebuilt.map(Body::new);
            if let Some(p) = peer {
                rebuilt.extensions_mut().insert(p);
            }
            rebuilt.extensions_mut().insert(Ohttp);
            next.run(rebuilt).await
        }
        Err(e) => e.into_response().map(Body::new),
    };
    match encapsulate_response(inner, server_response).await {
        Ok(r) => r.map(Body::new),
        Err(e) => plain(e),
    }
}

fn plain(e: OhttpError) -> Response {
    let mut r = e.into_response().map(Body::new);
    if r.status() == StatusCode::OK {
        *r.status_mut() = StatusCode::BAD_REQUEST;
    }
    r
}

/// The gateway from a hex X25519 private key (64 hex characters), as upstream's `from_hex_key`.
pub fn gateway(hex_key: &str) -> anyhow::Result<Arc<OhttpGateway>> {
    Ok(Arc::new(OhttpGateway::from_hex_key(hex_key).map_err(|e| anyhow::anyhow!("OHTTP key: {e}"))?))
}
