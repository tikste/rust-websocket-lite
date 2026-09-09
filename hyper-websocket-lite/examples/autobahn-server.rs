#![warn(clippy::pedantic)]
#![allow(let_underscore_drop)]

use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_websocket_lite::{AsyncClient, server_upgrade};
use tokio::net::TcpListener;
use websocket_codec::{Message, Opcode, Result};

async fn on_client(mut stream_mut: AsyncClient) {
    let mut stream = loop {
        let (msg, mut stream) = stream_mut.into_future().await;

        let msg = match msg {
            Some(Ok(msg)) => msg,
            Some(Err(_err)) => {
                let _ = stream.send(Message::close()).await;
                break stream;
            }
            None => {
                break stream;
            }
        };

        let _ = match msg.opcode() {
            Opcode::Text | Opcode::Binary => stream.send(msg).await,
            Opcode::Ping => stream.send(Message::pong(msg.into_data())).await,
            Opcode::Close => {
                break stream;
            }
            Opcode::Pong => Ok(()),
        };

        stream_mut = stream;
    };

    let _ = stream.send(Message::close()).await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 9001));
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
