use anyhow::Result;
use tunnelbore::protocol::server::Server;
use tunnelbore_macros::*;

#[tokio::main]
async fn main() -> Result<()> {
    let priv_key = b64!("<redacted>");
    let mut server = Server::new(":::1347").await?;
    server.run(priv_key).await?;
    Ok(())
}
