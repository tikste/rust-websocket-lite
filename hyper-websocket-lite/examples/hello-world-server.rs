#![warn(clippy::pedantic)]
#![allow(let_underscore_drop)]

use std::env;
use std::net::SocketAddr;

use futures_util::SinkExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_websocket_lite::{AsyncClient, server_upgrade};
use tokio::net::TcpListener;
use websocket_codec::{Message, Result};

async fn on_client(mut client: AsyncClient) {
    let _ = client.send(Message::text("Hello, world!")).await;
    let _ = client.send(Message::close()).await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let port = env::args().nth(1).unwrap_or_else(|| "9001".to_owned()).parse()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            // `with_upgrades` is required for `hyper::upgrade::on` inside `server_upgrade` to complete.
            let result = http1::Builder::new()
                .serve_connection(io, service_fn(|req| server_upgrade(req, on_client)))
                .with_upgrades()
                .await;

            if let Err(err) = result {
                eprintln!("error serving connection: {err}");
            }
        });
    }
}
