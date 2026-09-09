#![warn(clippy::pedantic)]
#![warn(missing_docs)]

//! A WebSocket server implementation on hyper and websocket-lite.

use std::future::Future;

use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::task;
use tokio_util::codec::{Decoder, Framed};
use websocket_codec::{ClientRequest, MessageCodec};

pub use websocket_codec::Result;

/// The body type returned in response to a client's WebSocket Upgrade request.
///
/// The response never carries a body: it is either a `101 Switching Protocols` or an error status.
pub type Body = Empty<Bytes>;

/// Exposes a `Sink` and a `Stream` for sending and receiving WebSocket messages asynchronously.
pub type AsyncClient = Framed<TokioIo<Upgraded>, MessageCodec>;

/// Accepts a client's WebSocket Upgrade request.
///
/// The connection serving `request` must have upgrades enabled, which for hyper's HTTP/1 server means
/// calling [`hyper::server::conn::http1::Connection::with_upgrades`] on the connection future.
///
/// # Errors
///
/// This method fails when a header required for the WebSocket protocol is missing in the request.
// The upgrade is driven by a spawned task, so nothing is awaited here. The signature stays `async` so that
// the function can be passed straight to `hyper::service::service_fn`.
#[allow(clippy::unused_async)]
pub async fn server_upgrade<OnClient, F>(request: Request<Incoming>, on_client: OnClient) -> Result<Response<Body>>
where
    OnClient: FnOnce(AsyncClient) -> F + Send + 'static,
    F: Future<Output = ()> + Send,
{
    let mut response = Response::new(Body::new());

    let ws_accept = if let Ok(req) = ClientRequest::parse(|name| {
        let h = request.headers().get(name)?;
        h.to_str().ok()
    }) {
        req.ws_accept()
    } else {
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(response);
    };

    task::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded) => {
                let client = MessageCodec::server().framed(TokioIo::new(upgraded));
                on_client(client).await;
            }
            Err(e) => eprintln!("upgrade error: {e}"),
        }
    });

    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

    let headers = response.headers_mut();
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::SEC_WEBSOCKET_ACCEPT, HeaderValue::from_str(&ws_accept)?);
    Ok(response)
}
