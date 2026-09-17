include!(concat!(env!("OUT_DIR"), "/tests.rs"));
include!(concat!(env!("OUT_DIR"), "/tests.serde.rs"));

use std::sync::{Arc, Mutex};

use futures::StreamExt as _;
use tokio::task::JoinSet;

use super::rpc_impl::RpcController;

#[derive(Clone, Default)]
struct GreetingJsonCallHandler;

#[async_trait::async_trait]
impl crate::proto::rpc_types::handler::Handler for GreetingJsonCallHandler {
    type Descriptor = GreetingDescriptor;
    type Controller = crate::proto::rpc_types::controller::BaseController;

    async fn call(
        &self,
        _ctrl: Self::Controller,
        method: <Self::Descriptor as crate::proto::rpc_types::descriptor::ServiceDescriptor>::Method,
        input: bytes::Bytes,
    ) -> crate::proto::rpc_types::error::Result<bytes::Bytes> {
        use prost::Message;
        match method {
            GreetingMethodDescriptor::SayHello => {
                let req = SayHelloRequest::decode(input)?;
                let resp = SayHelloResponse {
                    greeting: format!("Hello {}!", req.name),
                };
                Ok(bytes::Bytes::from(resp.encode_to_vec()))
            }
            GreetingMethodDescriptor::SayGoodbye => {
                let req = SayGoodbyeRequest::decode(input)?;
                let resp = SayGoodbyeResponse {
                    greeting: format!("Goodbye, {}!", req.name),
                };
                Ok(bytes::Bytes::from(resp.encode_to_vec()))
            }
        }
    }
}

#[derive(Clone)]
pub struct GreetingService {
    pub delay_ms: u64,
    pub prefix: String,
}

#[async_trait::async_trait]
impl Greeting for GreetingService {
    type Controller = RpcController;
    async fn say_hello(
        &self,
        _ctrl: Self::Controller,
        input: SayHelloRequest,
    ) -> crate::proto::rpc_types::error::Result<SayHelloResponse> {
        let resp = SayHelloResponse {
            greeting: format!("{} {}!", self.prefix, input.name),
        };
        tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        Ok(resp)
    }
    /// Generates a "goodbye" greeting based on the supplied info.
    async fn say_goodbye(
        &self,
        _ctrl: Self::Controller,
        input: SayGoodbyeRequest,
    ) -> crate::proto::rpc_types::error::Result<SayGoodbyeResponse> {
        let resp = SayGoodbyeResponse {
            greeting: format!("Goodbye, {}!", input.name),
        };
        tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        Ok(resp)
    }
}

use crate::proto::common::RpcCompressionInfo;
use crate::proto::rpc_impl::client::Client;
use crate::proto::rpc_impl::packet::supported_rpc_compression;
use crate::proto::rpc_impl::server::Server;

struct TestContext {
    client: Client,
    server: Server,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl TestContext {
    fn new() -> Self {
        let rpc_server = Server::new();
        rpc_server.run();

        let client = Client::new();
        client.run();

        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let (mut rx, tx) = (
            rpc_server.get_transport_stream(),
            client.get_transport_sink(),
        );

        tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                if let Err(err) = tx.send(packet).await {
                    println!("{:?}", err);
                    break;
                }
            }
        });

        let (mut rx, tx) = (
            client.get_transport_stream(),
            rpc_server.get_transport_sink(),
        );
        tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                if let Err(err) = tx.send(packet).await {
                    println!("{:?}", err);
                    break;
                }
            }
        });

        Self {
            client,
            server: rpc_server,
            tasks,
        }
    }
}

fn random_string(len: usize) -> String {
    use rand::Rng;
    use rand::distributions::Alphanumeric;
    let mut rng = rand::thread_rng();
    let s: Vec<u8> = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(len)
        .collect();
    String::from_utf8(s).unwrap()
}
