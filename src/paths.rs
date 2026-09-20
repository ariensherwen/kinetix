//! Filesystem layout for a standalone install.
//!
//! Kinetix is shipped as a single binary that a user installs into their home
//! directory. All state lives under XDG base directories so it never collides
//! with other tooling and is easy to back up or remove:
//!
//! - config: `$XDG_CONFIG_HOME/kinetix` (default `~/.config/kinetix`)
//! - data:   `$XDG_DATA_HOME/kinetix` (default `~/.local/share/kinetix`)
//! - state:  `$XDG_STATE_HOME/kinetix` (default `~/.local/state/kinetix`)
//!
//! Every directory can be overridden with an env var (`KINETIX_CONFIG_DIR`,
//! `KINETIX_DATA_DIR`, `KINETIX_STATE_DIR`) or the global `--home <dir>` CLI
//! flag, which places all three under one root. The database, exports, backups,
//! and master key all derive from these roots.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    /// Resolve the directory layout, honoring an optional `--home` override
    /// first, then per-directory env vars, then the XDG defaults.
    pub fn resolve(home_override: Option<&Path>) -> Self {
        if let Some(home) = home_override {
            return Paths {
                config_dir: home.join("config"),
                data_dir: home.join("data"),
                state_dir: home.join("state"),
            };
        }

        let config_dir = env_dir("KINETIX_CONFIG_DIR")
            .unwrap_or_else(|| xdg_dir("XDG_CONFIG_HOME", ".config").join("kinetix"));
        let data_dir = env_dir("KINETIX_DATA_DIR")
            .unwrap_or_else(|| xdg_dir("XDG_DATA_HOME", ".local/share").join("kinetix"));
        let state_dir = env_dir("KINETIX_STATE_DIR")
            .unwrap_or_else(|| xdg_dir("XDG_STATE_HOME", ".local/state").join("kinetix"));

        Paths {
            config_dir,
            data_dir,
            state_dir,
        }
    }

    /// The TOML config file.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// The master encryption key file (0600).
    pub fn master_key_file(&self) -> PathBuf {
        self.config_dir.join("master.key")
    }

    /// The SQLite database file.
    pub fn database_file(&self) -> PathBuf {
        self.data_dir.join("kinetix.db")
    }

    /// `sqlite://` URL for the database file, with create-if-missing.
    pub fn database_url(&self) -> String {
        format!("sqlite://{}?mode=rwc", self.database_file().display())
    }

    /// Exported per-day usage/log files.
    pub fn exports_dir(&self) -> PathBuf {
        self.data_dir.join("exports")
    }

    /// Scheduled and pre-migration database backups.
    pub fn backups_dir(&self) -> PathBuf {
        self.data_dir.join("backups")
    }

    /// Immutable, content-addressed copies of accepted `.kxp` packages.
    pub fn plugin_packages_dir(&self) -> PathBuf {
        self.data_dir.join("plugins").join("packages")
    }

    /// Operational logs (only used when the process is run detached).
    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("kinetix.log")
    }

    /// Create the directory tree with owner-only permissions where appropriate.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for d in [&self.config_dir, &self.data_dir, &self.state_dir] {
            std::fs::create_dir_all(d)?;
        }
        std::fs::create_dir_all(self.exports_dir())?;
        std::fs::create_dir_all(self.backups_dir())?;
        std::fs::create_dir_all(self.plugin_packages_dir())?;
        Ok(())
    }
}

fn env_dir(key: &str) -> Option<PathBuf> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
}

/// Resolve an XDG directory: the env var if set, else `$HOME/<fallback>`.
fn xdg_dir(env_key: &str, fallback: &str) -> PathBuf {
    if let Ok(v) = std::env::var(env_key) {
        if !v.trim().is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(fallback)
}

/// The directory the installer drops the binary into (`~/.local/bin`).
pub fn bin_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/bin")
}
