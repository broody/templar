//! Oblivious HTTP (RFC 9458) client encapsulation, the server's own crates (spec §8). The key
//! configuration is pinned or supplied by the application; a request is a Binary HTTP message.
use std::io::Cursor;

use crate::{Error, Result};

/// An encapsulated request and the state that opens its response.
pub struct Pending {
    pub envelope: Vec<u8>,
    pub context: ohttp::ClientResponse,
}

/// Encapsulates `method path` with a JSON body under the key configuration list `config`.
pub fn encapsulate(config: &[u8], method: &str, path: &str, body: &[u8]) -> Result<Pending> {
    let mut request = bhttp::Message::request(method.as_bytes().to_vec(), b"https".to_vec(), b"".to_vec(), path.as_bytes().to_vec());
    request.put_header("content-type", "application/json");
    request.write_content(body);
    let mut bytes = Vec::new();
    request.write_bhttp(bhttp::Mode::KnownLength, &mut bytes).map_err(|e| Error::new("ohttp", format!("bhttp: {e}")))?;
    let (envelope, context) = ohttp::ClientRequest::from_encoded_config_list(config)
        .map_err(|e| Error::new("ohttp", format!("key configuration: {e}")))?
        .encapsulate(&bytes)
        .map_err(|e| Error::new("ohttp", format!("encapsulation: {e}")))?;
    Ok(Pending { envelope, context })
}

/// Opens a response: `(status, body)`.
pub fn decapsulate(context: ohttp::ClientResponse, response: &[u8]) -> Result<(u16, Vec<u8>)> {
    let inner = context.decapsulate(response).map_err(|e| Error::new("ohttp", format!("decapsulation: {e}")))?;
    let m = bhttp::Message::read_bhttp(&mut Cursor::new(&inner)).map_err(|e| Error::new("ohttp", format!("bhttp: {e}")))?;
    Ok((m.control().status().map(|s| s.code()).unwrap_or(0), m.content().to_vec()))
}
