use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroize;

use crate::fingerprint::{FingerprintKey, KEY_ID_LENGTH, KEY_LENGTH};

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    ttl_seconds INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(profile_id, name)
);

CREATE INDEX IF NOT EXISTS secrets_profile_id_idx ON secrets(profile_id);

CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    fingerprint_key BLOB NOT NULL,
    fingerprint_key_id BLOB NOT NULL
);
"#;

pub fn default_vault_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "no-clone")
        .context("could not determine the current user's data directory")?;
    Ok(dirs.data_dir().join("vault.db"))
}

pub struct Vault {
    path: PathBuf,
    connection: Connection,
}

#[derive(Debug)]
pub struct ProfileSummary {
    pub name: String,
    pub ttl_seconds: i64,
    pub secret_count: i64,
}

#[derive(Debug)]
pub struct SecretSummary {
    pub name: String,
    pub byte_len: usize,
}

#[allow(dead_code)]
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct VaultSecret {
    pub name: String,
    pub value: Vec<u8>,
}

impl Vault {
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        if password.is_empty() {
            bail!("vault password cannot be empty");
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let connection = Connection::open(path)
            .with_context(|| format!("failed to create vault at {}", path.display()))?;
        configure_connection(&connection, password)?;
        connection.execute_batch(SCHEMA)?;
        let fingerprint_key = FingerprintKey::generate();
        connection.execute(
            "INSERT INTO vault_metadata (id, fingerprint_key, fingerprint_key_id)
             VALUES (1, ?1, ?2)",
            params![
                fingerprint_key.key_bytes(),
                fingerprint_key.key_id().as_slice()
            ],
        )?;
        restrict_file_permissions(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            connection,
        })
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        if password.is_empty() {
            bail!("vault password cannot be empty");
        }

        let connection = Connection::open(path)
            .with_context(|| format!("failed to open vault at {}", path.display()))?;
        configure_connection(&connection, password)?;

        // Force a read after keying the database. A wrong password otherwise may
        // remain undetected until the first real query.
        let _: i64 = connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .context("could not unlock vault; check the password")?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        Ok(Self {
            path: path.to_path_buf(),
            connection,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.is_empty() {
            bail!("vault password cannot be empty");
        }

        self.connection
            .pragma_update(None, "rekey", new_password)
            .context("failed to change vault password")?;

        // Confirm that this connection can still read the database after the
        // rekey operation. The caller separately verifies the persisted key
        // by reopening the file with the new password.
        let _: i64 = self
            .connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .context("could not verify changed vault password")?;
        Ok(())
    }

    pub fn fingerprint_key(&self) -> Result<FingerprintKey> {
        let (key, key_id): (Vec<u8>, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT fingerprint_key, fingerprint_key_id FROM vault_metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("vault fingerprint key is missing")?;
        if key.len() != KEY_LENGTH || key_id.len() != KEY_ID_LENGTH {
            bail!("vault fingerprint key has invalid metadata");
        }
        FingerprintKey::from_parts(key, key_id)
    }

    pub fn rotate_fingerprint_key(&mut self) -> Result<FingerprintKey> {
        let fingerprint_key = FingerprintKey::generate();
        let transaction = self.connection.transaction()?;
        let updated = transaction.execute(
            "UPDATE vault_metadata SET fingerprint_key = ?1, fingerprint_key_id = ?2 WHERE id = 1",
            params![
                fingerprint_key.key_bytes(),
                fingerprint_key.key_id().as_slice()
            ],
        )?;
        if updated != 1 {
            bail!("vault fingerprint key is missing");
        }
        transaction.commit()?;
        Ok(fingerprint_key)
    }

    pub fn create_profile(&mut self, name: &str, ttl_seconds: i64) -> Result<()> {
        let now = unix_time()?;
        self.connection
            .execute(
                "INSERT INTO profiles (name, ttl_seconds, created_at) VALUES (?1, ?2, ?3)",
                params![name, ttl_seconds, now],
            )
            .with_context(|| format!("profile '{name}' already exists or could not be created"))?;
        Ok(())
    }

    pub fn delete_profile(&mut self, name: &str) -> Result<()> {
        let deleted = self
            .connection
            .execute("DELETE FROM profiles WHERE name = ?1", params![name])?;
        if deleted == 0 {
            bail!("profile '{name}' does not exist");
        }
        Ok(())
    }

    pub fn list_profiles(&self) -> Result<Vec<ProfileSummary>> {
        let mut statement = self.connection.prepare(
            "SELECT p.name, p.ttl_seconds, count(s.id)
             FROM profiles p
             LEFT JOIN secrets s ON s.profile_id = p.id
             GROUP BY p.id, p.name, p.ttl_seconds
             ORDER BY p.name",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ProfileSummary {
                name: row.get(0)?,
                ttl_seconds: row.get(1)?,
                secret_count: row.get(2)?,
            })
        })?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list profiles")
    }

    pub fn put_secret(&mut self, profile: &str, name: &str, value: &[u8]) -> Result<()> {
        let profile_id: i64 = self
            .connection
            .query_row(
                "SELECT id FROM profiles WHERE name = ?1",
                params![profile],
                |row| row.get(0),
            )
            .with_context(|| format!("profile '{profile}' does not exist"))?;
        let now = unix_time()?;

        self.connection.execute(
            "INSERT INTO secrets (profile_id, name, value, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(profile_id, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![profile_id, name, value, now],
        )?;
        Ok(())
    }

    pub fn delete_secret(&mut self, profile: &str, name: &str) -> Result<()> {
        let deleted = self.connection.execute(
            "DELETE FROM secrets
             WHERE profile_id = (SELECT id FROM profiles WHERE name = ?1) AND name = ?2",
            params![profile, name],
        )?;
        if deleted == 0 {
            bail!("secret '{profile}/{name}' does not exist");
        }
        Ok(())
    }

    pub fn list_secrets(&self, profile: &str) -> Result<Vec<SecretSummary>> {
        let profile_id: Option<i64> = self
            .connection
            .query_row(
                "SELECT id FROM profiles WHERE name = ?1",
                params![profile],
                |row| row.get(0),
            )
            .optional()?;
        let Some(profile_id) = profile_id else {
            bail!("profile '{profile}' does not exist");
        };

        let mut statement = self.connection.prepare(
            "SELECT name, length(value) FROM secrets WHERE profile_id = ?1 ORDER BY name",
        )?;
        let rows = statement.query_map(params![profile_id], |row| {
            Ok(SecretSummary {
                name: row.get(0)?,
                byte_len: row.get::<_, i64>(1)? as usize,
            })
        })?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list secrets")
    }

    #[allow(dead_code)]
    pub fn get_secret(&self, profile: &str, name: &str) -> Result<VaultSecret> {
        let result = self.connection.query_row(
            "SELECT s.name, s.value
             FROM secrets s
             JOIN profiles p ON p.id = s.profile_id
             WHERE p.name = ?1 AND s.name = ?2",
            params![profile, name],
            |row| {
                Ok(VaultSecret {
                    name: row.get(0)?,
                    value: row.get(1)?,
                })
            },
        );

        result.with_context(|| format!("secret '{profile}/{name}' does not exist"))
    }

    pub fn load_profile(&self, profile: &str) -> Result<(i64, Vec<VaultSecret>)> {
        let (profile_id, ttl_seconds): (i64, i64) = self
            .connection
            .query_row(
                "SELECT id, ttl_seconds FROM profiles WHERE name = ?1",
                params![profile],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| format!("profile '{profile}' does not exist"))?;

        let mut statement = self
            .connection
            .prepare("SELECT name, value FROM secrets WHERE profile_id = ?1 ORDER BY name")?;
        let rows = statement.query_map(params![profile_id], |row| {
            Ok(VaultSecret {
                name: row.get(0)?,
                value: row.get(1)?,
            })
        })?;

        let secrets = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to load profile secrets")?;
        Ok((ttl_seconds, secrets))
    }
}

fn configure_connection(connection: &Connection, password: &str) -> Result<()> {
    connection
        .pragma_update(None, "key", password)
        .context("failed to configure vault encryption")?;
    connection
        .pragma_update(None, "cipher_compatibility", 4)
        .context("failed to configure SQLCipher compatibility")?;
    Ok(())
}

fn unix_time() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64)
}

fn restrict_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "no-clone-vault-test-{}-{}-{}.db",
            std::process::id(),
            unix_time().expect("clock should be available"),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn creates_reopens_and_rejects_wrong_password() {
        let path = test_path();

        {
            let mut vault = Vault::create(&path, "correct horse battery staple").unwrap();
            vault.create_profile("production", 1800).unwrap();
            vault
                .put_secret("production", "binary", &[0, 1, 2, 255])
                .unwrap();

            let profiles = vault.list_profiles().unwrap();
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].secret_count, 1);
        }

        {
            let vault = Vault::open(&path, "correct horse battery staple").unwrap();
            let secret = vault.get_secret("production", "binary").unwrap();
            assert_eq!(secret.value, vec![0, 1, 2, 255]);
        }

        assert!(Vault::open(&path, "wrong password").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn changes_password_without_losing_vault_data() {
        let path = test_path();

        {
            let mut vault = Vault::create(&path, "old-password").unwrap();
            vault.create_profile("production", 1800).unwrap();
            vault
                .put_secret("production", "token", &[0, 1, 2, 255])
                .unwrap();
            vault.change_password("new-password").unwrap();
        }

        assert!(Vault::open(&path, "old-password").is_err());
        let vault = Vault::open(&path, "new-password").unwrap();
        assert_eq!(
            vault.get_secret("production", "token").unwrap().value,
            vec![0, 1, 2, 255]
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn fingerprint_key_survives_password_change_and_rotates() {
        let path = test_path();

        let original_id = {
            let mut vault = Vault::create(&path, "old-password").unwrap();
            let original_id = *vault.fingerprint_key().unwrap().key_id();
            vault.change_password("new-password").unwrap();
            original_id
        };

        let mut vault = Vault::open(&path, "new-password").unwrap();
        assert_eq!(*vault.fingerprint_key().unwrap().key_id(), original_id);
        let rotated_id = *vault.rotate_fingerprint_key().unwrap().key_id();
        assert_ne!(rotated_id, original_id);
        assert_eq!(*vault.fingerprint_key().unwrap().key_id(), rotated_id);

        fs::remove_file(path).unwrap();
    }
}
