//! Turso-Datenbank (lokale Datei, mit AEGIS-256 verschluesselt) und Schema-Migrationen.

use std::path::Path;
use tokio::sync::{Mutex, MutexGuard};
use turso::{Builder, Connection, Database, EncryptionOpts, Value};

pub struct Db {
    _db: Database,
    conn: Mutex<Connection>,
}

pub type Conn<'a> = MutexGuard<'a, Connection>;
pub type Row = Vec<Value>;

const MIGRATIONS: &[&str] = &[
    // 1: Grundschema
    r#"
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        name TEXT,
        pw_hash TEXT NOT NULL,
        hint TEXT,
        akey TEXT NOT NULL,
        private_key TEXT,
        public_key TEXT,
        kdf INTEGER NOT NULL,
        kdf_iter INTEGER NOT NULL,
        kdf_mem INTEGER,
        kdf_par INTEGER,
        security_stamp TEXT NOT NULL,
        totp_secret TEXT,
        totp_last_step INTEGER NOT NULL DEFAULT 0,
        created_ms INTEGER NOT NULL,
        revision_ms INTEGER NOT NULL,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        identifier TEXT NOT NULL,
        name TEXT NOT NULL,
        dtype INTEGER NOT NULL,
        refresh_hash TEXT,
        refresh_expires INTEGER NOT NULL DEFAULT 0,
        remember_hash TEXT,
        remember_expires INTEGER NOT NULL DEFAULT 0,
        created_ms INTEGER NOT NULL,
        last_seen_ms INTEGER NOT NULL
    );
    CREATE INDEX devices_user ON devices(user_id);
    CREATE INDEX devices_refresh ON devices(refresh_hash);
    CREATE TABLE old_refresh (
        hash TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        expires INTEGER NOT NULL
    );
    CREATE TABLE access_tokens (
        hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        expires INTEGER NOT NULL
    );
    CREATE INDEX access_tokens_device ON access_tokens(device_id);
    CREATE TABLE folders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        revision_ms INTEGER NOT NULL
    );
    CREATE INDEX folders_user ON folders(user_id);
    CREATE TABLE ciphers (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        folder_id TEXT,
        ctype INTEGER NOT NULL,
        favorite INTEGER NOT NULL DEFAULT 0,
        data TEXT NOT NULL,
        created_ms INTEGER NOT NULL,
        revision_ms INTEGER NOT NULL,
        deleted_ms INTEGER
    );
    CREATE INDEX ciphers_user ON ciphers(user_id);
    CREATE TABLE linked_accounts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        data TEXT NOT NULL,
        revision_ms INTEGER NOT NULL
    );
    CREATE INDEX linked_user ON linked_accounts(user_id);
    CREATE TABLE events (
        id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        ip TEXT,
        device TEXT,
        at_ms INTEGER NOT NULL
    );
    CREATE INDEX events_user ON events(user_id);
    "#,
];

impl Db {
    pub async fn open(path: &Path, hexkey: &str) -> Result<Db, String> {
        let p = path.to_str().ok_or("Pfad der Datenbank ist kein UTF-8")?;
        let db = Builder::new_local(p)
            .experimental_encryption(true)
            .with_encryption(EncryptionOpts { cipher: "aegis256".into(), hexkey: hexkey.to_string() })
            .build()
            .await
            .map_err(|e| {
                format!("Datenbank {p} laesst sich nicht oeffnen ({e}). Falscher Schluessel (NRZPASS_SEED/NRZPASS_DB_KEY/db.key)?")
            })?;
        let conn = db.connect().map_err(|e| e.to_string())?;
        // Bei kurzzeitig gesperrter Datei warten statt sofort scheitern
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        Ok(Db { _db: db, conn: Mutex::new(conn) })
    }

    pub async fn lock(&self) -> Conn<'_> {
        self.conn.lock().await
    }

    pub async fn migrate(&self) -> Result<(), String> {
        let c = self.lock().await;
        let rows = query(&c, "PRAGMA user_version", vec![]).await.map_err(|e| e.to_string())?;
        let current = rows.first().and_then(|r| r.first()).map(int).unwrap_or(0) as usize;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(current) {
            c.execute_batch(format!("BEGIN; {m}; PRAGMA user_version = {}; COMMIT;", i + 1))
                .await
                .map_err(|e| format!("Migration {}: {e}", i + 1))?;
        }
        Ok(())
    }
}

pub async fn query(c: &Connection, sql: &str, params: Vec<Value>) -> turso::Result<Vec<Row>> {
    let mut rows = c.query(sql, params).await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        let mut v = Vec::with_capacity(r.column_count());
        for i in 0..r.column_count() {
            v.push(r.get_value(i)?);
        }
        out.push(v);
    }
    Ok(out)
}

pub async fn query_one(c: &Connection, sql: &str, params: Vec<Value>) -> turso::Result<Option<Row>> {
    Ok(query(c, sql, params).await?.into_iter().next())
}

pub async fn exec(c: &Connection, sql: &str, params: Vec<Value>) -> turso::Result<u64> {
    c.execute(sql, params).await
}

pub fn text(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Integer(i) => i.to_string(),
        _ => String::new(),
    }
}

pub fn opt_text(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

pub fn int(v: &Value) -> i64 {
    match v {
        Value::Integer(i) => *i,
        Value::Real(f) => *f as i64,
        Value::Text(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

pub fn opt_int(v: &Value) -> Option<i64> {
    match v {
        Value::Null => None,
        v => Some(int(v)),
    }
}

/// Kurzform fuer Parameterlisten: `p![a, b, c]`.
#[macro_export]
macro_rules! p {
    ($($x:expr),* $(,)?) => { vec![$(turso::Value::from($x)),*] };
}
