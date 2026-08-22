use std::{ffi::OsString, path::PathBuf};

use clap::Parser;

/// Command line contract kept compatible with earlier msgtausch releases.
#[derive(Clone, Debug, Parser, PartialEq, Eq)]
#[command(name = "msgtausch", disable_version_flag = true)]
pub struct Cli {
    /// Path to a JSON or HCL configuration file. May be specified more than once.
    #[arg(long, value_name = "PATH")]
    pub config: Vec<PathBuf>,

    /// Path to a dotenv file. Its values override the inherited environment.
    #[arg(long, value_name = "PATH")]
    pub envfile: Option<PathBuf>,

    /// Enable debug logging.
    #[arg(long)]
    pub debug: bool,

    /// Enable trace logging.
    #[arg(long)]
    pub trace: bool,

    /// Print the version and exit.
    #[arg(long, short = 'v')]
    pub version: bool,
}

impl Cli {
    /// Parse legacy flag spellings (`-config`) and conventional long options
    /// (`--config`) during the migration.
    pub fn parse_compatible() -> Self {
        Self::parse_from(normalize_go_flags(std::env::args_os()))
    }

    /// Returns supplied paths, or the legacy implicit `config.json` path.
    pub fn config_paths(&self) -> Vec<PathBuf> {
        if self.config.is_empty() {
            vec![PathBuf::from("config.json")]
        } else {
            self.config.clone()
        }
    }
}

fn normalize_go_flags(arguments: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    arguments
        .into_iter()
        .map(|argument| match argument.to_str() {
            Some("-config") => "--config".into(),
            Some("-envfile") => "--envfile".into(),
            Some("-debug") => "--debug".into(),
            Some("-trace") => "--trace".into(),
            Some("-version") => "--version".into(),
            _ => argument,
        })
        .collect()
}

pub fn version_string() -> String {
    format!(
        "msgtausch version: {}",
        option_env!("MSGTAUSCH_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;
    use super::normalize_go_flags;

    #[test]
    fn repeated_config_paths_and_short_version_work() {
        let cli =
            Cli::try_parse_from(["msgtausch", "--config", "a.json", "--config", "b.hcl", "-v"])
                .unwrap();
        assert_eq!(cli.config_paths().len(), 2);
        assert!(cli.version);
    }

    #[test]
    fn go_single_dash_flags_remain_accepted() {
        let arguments = normalize_go_flags(
            ["msgtausch", "-config", "a.json", "-debug"]
                .into_iter()
                .map(Into::into),
        );
        let cli = Cli::try_parse_from(arguments).unwrap();
        assert_eq!(cli.config_paths(), [std::path::PathBuf::from("a.json")]);
        assert!(cli.debug);
    }
}
