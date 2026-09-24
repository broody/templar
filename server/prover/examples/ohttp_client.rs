//! A minimal OHTTP client for testing the server (RFC 9458): fetches `/ohttp-keys`, sends one
//! request inside an envelope, and prints the inner status and body.
//! `ohttp_client BASE_URL METHOD PATH [BODY_FILE]` (a relay would sit between client and server).
use std::io::Cursor;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    anyhow::ensure!(a.len() >= 4, "ohttp_client BASE_URL METHOD PATH [BODY_FILE]");
    let (base, method, path) = (&a[1], &a[2], &a[3]);
    let body = a.get(4).map(std::fs::read).transpose()?.unwrap_or_default();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let http = reqwest::Client::new();
        let config = http.get(format!("{base}/ohttp-keys")).send().await?.bytes().await?;
        let mut request = bhttp::Message::request(method.as_bytes().to_vec(), b"https".to_vec(), b"".to_vec(), path.as_bytes().to_vec());
        request.put_header("content-type", "application/json");
        request.write_content(&body);
        let mut bytes = Vec::new();
        request.write_bhttp(bhttp::Mode::KnownLength, &mut bytes)?;
        let (envelope, context) = ohttp::ClientRequest::from_encoded_config_list(&config)?.encapsulate(&bytes)?;
        let reply = http.post(format!("{base}/")).header("content-type", "message/ohttp-req").body(envelope).send().await?;
        let outer = reply.status();
        let encrypted = reply.bytes().await?;
        let inner = bhttp::Message::read_bhttp(&mut Cursor::new(&context.decapsulate(&encrypted)?))?;
        println!("outer {outer} inner {} {}", inner.control().status().map(|s| s.code()).unwrap_or(0),
                 String::from_utf8_lossy(inner.content()).chars().take(400).collect::<String>());
        anyhow::Ok(())
    })
}
