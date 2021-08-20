use bytes::{Bytes, BytesMut};
use eyre::{eyre, Result};
use futures::SinkExt;
use postgres_native_tls::TlsConnector;
use postgres_native_tls::TlsStream;
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use rusoto_credential::ChainProvider;
use rusoto_credential::ProvideAwsCredentials;
use rusoto_signature::Region;
use rusoto_signature::SignedRequest;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_postgres::tls::TlsConnect;
use tokio_stream::StreamExt;
use tokio_util::codec::BytesCodec;
use tokio_util::codec::Framed;

#[derive(Debug)]
pub struct DbSpec {
  user: String,
  database: String,
}

impl DbSpec {
  pub fn new(user: String, database: String) -> DbSpec {
    DbSpec {
      user: user,
      database: database,
    }
  }

  fn startup_message(&self) -> Result<Bytes> {
    let mut params = vec![("client_encoding", "UTF8")];
    params.push(("user", self.user.as_str()));
    params.push(("database", self.database.as_str()));
    let mut buf = BytesMut::new();
    frontend::startup_message(params, &mut buf)?;
    Ok(buf.freeze())
  }
}

#[derive(Clone, Debug, Deserialize)]
struct Addr {
  hostname: String,
  port: u16,
}

impl Addr {
  fn connect_str(&self) -> String {
    format!("{}:{}", self.hostname, self.port)
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BackendConfig {
  endpoint: Addr,
  region: String,
  proxy_endpoint: Option<Addr>,
}

impl BackendConfig {
  fn connect_endpoint(&self) -> &Addr {
    match self.proxy_endpoint {
      Some(ref proxy) => &proxy,
      None => &self.endpoint,
    }
  }

  pub async fn get_server_conn(&self, db_spec: DbSpec) -> Result<TlsStream<TcpStream>> {
    let password = get_rds_password(
      self.endpoint.hostname.as_ref(),
      self.endpoint.port,
      self.region.as_ref(),
      db_spec.user.as_str(),
    )
    .await?;
    let stream = self.backend_conn(db_spec, password).await?;
    Ok(stream)
  }

  async fn backend_conn(&self, db_spec: DbSpec, password: String) -> Result<TlsStream<TcpStream>> {
    let stream = TcpStream::connect(self.connect_endpoint().connect_str()).await?;
    let mut tls_stream = self.upgrade_to_tls(stream).await?;
    send_password(&db_spec, &mut tls_stream, password).await?;
    Ok(tls_stream)
  }

  async fn upgrade_to_tls<S>(&self, mut tcp: S) -> Result<TlsStream<S>>
  where
    S: AsyncRead + AsyncWrite + Unpin + 'static + Send,
  {
    let mut buf = BytesMut::new();
    frontend::ssl_request(&mut buf);
    tcp.write_all(&buf).await?;
    let mut buf = [0];
    tcp.read_exact(&mut buf).await?;
    if buf[0] != b'S' {
      Err(eyre!("server does not support TLS"))
    } else {
      let native_conn = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
      let tls = TlsConnector::new(native_conn, self.endpoint.hostname.as_ref());
      let stream = tls.connect(tcp).await?;
      Ok(stream)
    }
  }
}

const HTTPS_LEN: usize = "https://".len();

async fn get_rds_password(
  rds_host: &str,
  port: u16,
  region_name: &str,
  username: &str,
) -> Result<String> {
  let provider = ChainProvider::new();
  let creds = provider.credentials().await?;
  let region = Region::from_str(region_name)?;
  let mut request = SignedRequest::new("GET", "rds-db", &region, "/");
  request.set_hostname(Some(format!("{}:{}", rds_host, port)));
  request.add_param("Action", "connect");
  request.add_param("DBUser", username);
  let expires_in = Duration::from_secs(15 * 60);
  let mut signature = request.generate_presigned_url(&creds, &expires_in, true);
  let password = signature.split_off(HTTPS_LEN);
  Ok(password)
}

async fn send_password<S>(db_spec: &DbSpec, stream: &mut S, password: String) -> Result<()>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let buf = db_spec.startup_message()?;
  let mut framed = Framed::new(stream, BytesCodec::new());
  framed.send(buf).await?;
  if let Some(mut resp) = framed.try_next().await? {
    if let Ok(Some(Message::AuthenticationCleartextPassword)) = Message::parse(&mut resp) {
      let mut pw_buf = BytesMut::new();
      frontend::password_message(password.as_ref(), &mut pw_buf)?;
      framed.send(pw_buf.freeze()).await?;
      Ok(())
    } else {
      Err(eyre!("Unexpected auth prompt"))
    }
  } else {
    Err(eyre!("Unexpected backed message"))
  }
}
