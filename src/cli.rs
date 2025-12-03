use std::path::PathBuf;
use crate::config::Config;
use crate::daemon::{DaemonClient, Command};

pub struct Cli {
    config: Config,
}

impl Cli {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run_command(&self, command: Command) -> anyhow::Result<()> {
        let client = DaemonClient::new(self.config.socket_path().clone());
        client.send_command(command).await?;
        Ok(())
    }
}
