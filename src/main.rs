#[macro_use]
extern crate serde_derive;

use crate::backend_config::DbSpec;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use bytes::Bytes;
use config::Config;
use config::File;
use eyre::{eyre, Result};
use futures::SinkExt;
use memchr::memchr;
use postgres_native_tls::TlsStream;
use std::net::SocketAddr;
use tokio::io::split;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Decoder};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

mod backend_config;
use backend_config::BackendConfig;

fn setup() -> Result<()> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    Ok(())
}

const SSL_REQUEST: i32 = 80877103;
const STARTUP_MESSAGE: i32 = 196608;
const SSL_NOT_ALLOWED: u8 = 0x4e;

struct Buffer {
    bytes: Bytes,
    idx: usize,
}

impl Buffer {
    #[inline]
    fn slice(&self) -> &[u8] {
        &self.bytes[self.idx..]
    }

    #[inline]
    fn read_cstr(&mut self) -> std::io::Result<Bytes> {
        match memchr(0, self.slice()) {
            Some(pos) => {
                let start = self.idx;
                let end = start + pos;
                let cstr = self.bytes.slice(start..end);
                self.idx = end + 1;
                Ok(cstr)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            )),
        }
    }
}

fn parse_startup(src: Bytes) -> Result<DbSpec> {
    let mut user: Option<String> = None;
    let mut database: Option<String> = None;
    let mut buf = Buffer { bytes: src, idx: 0 };
    while user.is_none() || database.is_none() {
        let tag = buf.read_cstr()?;
        let value = buf.read_cstr()?;
        if tag == "user" {
            user = Some(std::str::from_utf8(&value[0..])?.to_owned());
        } else if tag == "database" {
            database = Some(std::str::from_utf8(&value[0..])?.to_owned());
        } else {
            debug!("ignoring tag {}", std::str::from_utf8(&tag[0..])?);
        }
    }
    let db = DbSpec::new(
        user.ok_or_else(|| eyre!("missing user"))?,
        database.ok_or_else(|| eyre!("missing database"))?,
    );
    Ok(db)
}

async fn auth_backend(
    config: &BackendConfig,
    client: &mut TcpStream,
) -> Result<TlsStream<TcpStream>> {
    let mut framed = BytesCodec::new().framed(client);
    while let Some(message) = framed.next().await {
        match message {
            Ok(mut bytes) => {
                if bytes.len() < 8 {
                    return Err(eyre!("Received too-small packet"));
                } else {
                    let len = BigEndian::read_i32(&bytes[0..]);
                    let tag = BigEndian::read_i32(&bytes[4..]);
                    if len == 8 && tag == SSL_REQUEST {
                        framed.send(Bytes::from_static(&[SSL_NOT_ALLOWED])).await?;
                    } else if tag == STARTUP_MESSAGE {
                        if bytes.len() < (len as usize) {
                            return Err(eyre!(
                                "Packet wanted {} bytes, provided {}",
                                len,
                                bytes.len()
                            ));
                        }
                        let db = parse_startup(bytes.split_off(8).freeze())?;
                        let server = config.get_server_conn(db).await?;
                        return Ok(server);
                    } else {
                        return Err(eyre!("Unknown message tag {}", tag));
                    }
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    Err(eyre!("Client closed"))
}

async fn handle_client(
    config: &BackendConfig,
    mut client: TcpStream,
    _addr: SocketAddr,
) -> Result<()> {
    let server = auth_backend(config, &mut client).await?;

    let (mut ri, mut wi) = client.split();
    let (mut ro, mut wo) = split(server);
    let client_to_server = async {
        tokio::io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        tokio::io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };
    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

async fn run_proxy(config: BackendConfig) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5435").await?;
    info!("Listening");
    loop {
        let (stream, addr) = listener.accept().await?;

        info!("Got connection");
        let config_copy = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(&config_copy, stream, addr).await {
                info!("An error occurred in a client {:?}", e);
            } else {
                info!("done with client");
            }
        });
    }
}

fn load_config() -> Result<BackendConfig> {
    let mut s = Config::default();
    s.merge(File::with_name("proxy"))?;
    s.try_into().map_err(|e| e.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;
    let backend_config = load_config()?;
    run_proxy(backend_config).await?;
    Ok(())
}
