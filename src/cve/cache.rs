// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Erreur base de données: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    #[error("Erreur sérialisation: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Chemin invalide: {0}")]
    PathError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub severity: Option<String>,
    pub published: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeRecord {
    pub id: Option<i64>,
    pub cve_id: String,
    pub cpe_name: String,
    pub vendor: String,
    pub product: String,
    pub version_start_including: Option<String>,
    pub version_end_excluding: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PackageRecord {
    pub name: String,
    pub version: String,
    pub distro: String,
    pub scanned_at: DateTime<Utc>,
}

pub struct CveCache {
    conn: Connection,
}

#[allow(dead_code)]
impl CveCache {
    pub fn new(db_path: PathBuf) -> Result<Self, CacheError> {
        let path = db_path.to_str().ok_or_else(|| {
            CacheError::PathError("Chemin base de données invalide".to_string())
        })?;
        let conn = Connection::open(path)?;
        let cache = Self { conn };
        cache.init_schema()?;
        Ok(cache)
    }

    pub fn in_memory() -> Result<Self, CacheError> {
        let conn = Connection::open_in_memory()?;
        let cache = Self { conn };
        cache.init_schema()?;
        Ok(cache)
    }

    fn init_schema(&self) -> Result<(), CacheError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                cvss_score REAL,
                severity TEXT,
                published TEXT NOT NULL,
                modified TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cpe (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                cpe_name TEXT NOT NULL,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                version_start_including TEXT,
                version_end_excluding TEXT,
                version_start_excluding TEXT,
                version_end_including TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(id)
            );
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                distro TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (name, version, distro)
            );
            CREATE INDEX IF NOT EXISTS idx_cpe_cve_id ON cpe(cve_id);
            CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe(vendor, product);
            "#,
        )?;
        Ok(())
    }

    pub fn upsert_cve(&self, cve: &CveRecord) -> Result<(), CacheError> {
        self.conn.execute(
            r#"
            INSERT INTO cves (id, description, cvss_score, severity, published, modified)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(id) DO UPDATE SET
                description = excluded.description,
                cvss_score = excluded.cvss_score,
                severity = excluded.severity,
                modified = excluded.modified
            "#,
            params![
                cve.id,
                cve.description,
                cve.cvss_score,
                cve.severity,
                cve.published.to_rfc3339(),
                cve.modified.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_cpe(&self, cpe: &CpeRecord) -> Result<(), CacheError> {
        self.conn.execute(
            r#"
            INSERT INTO cpe (cve_id, cpe_name, vendor, product, version_start_including, version_end_excluding, version_start_excluding, version_end_including)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                cpe.cve_id,
                cpe.cpe_name,
                cpe.vendor,
                cpe.product,
                cpe.version_start_including,
                cpe.version_end_excluding,
                cpe.version_start_excluding,
                cpe.version_end_including,
            ],
        )?;
        Ok(())
    }

    pub fn get_cve(&self, id: &str) -> Result<Option<CveRecord>, CacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, description, cvss_score, severity, published, modified FROM cves WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(CveRecord {
                id: row.get(0)?,
                description: row.get(1)?,
                cvss_score: row.get(2)?,
                severity: row.get(3)?,
                published: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?,
                modified: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn search_cves_by_cpe(
        &self,
        vendor: &str,
        product: &str,
    ) -> Result<Vec<(CveRecord, CpeRecord)>, CacheError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT c.id, c.description, c.cvss_score, c.severity, c.published, c.modified,
                   p.id, p.cve_id, p.cpe_name, p.vendor, p.product,
                   p.version_start_including, p.version_end_excluding, p.version_start_excluding, p.version_end_including
            FROM cves c
            JOIN cpe p ON c.id = p.cve_id
            WHERE p.vendor = ?1 AND p.product = ?2
            "#,
        )?;
        let rows = stmt.query_map(params![vendor, product], |row| {
            Ok((
                CveRecord {
                    id: row.get(0)?,
                    description: row.get(1)?,
                    cvss_score: row.get(2)?,
                    severity: row.get(3)?,
                    published: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap(),
                    modified: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap(),
                },
                CpeRecord {
                    id: row.get(6)?,
                    cve_id: row.get(7)?,
                    cpe_name: row.get(8)?,
                    vendor: row.get(9)?,
                    product: row.get(10)?,
                    version_start_including: row.get(11)?,
                    version_end_excluding: row.get(12)?,
                    version_start_excluding: row.get(13)?,
                    version_end_including: row.get(14)?,
                },
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn count_cves(&self) -> Result<i64, CacheError> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM cves")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    pub fn upsert_package(&self, pkg: &PackageRecord) -> Result<(), CacheError> {
        self.conn.execute(
            r#"
            INSERT INTO packages (name, version, distro, scanned_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(name, version, distro) DO UPDATE SET
                scanned_at = excluded.scanned_at
            "#,
            params![pkg.name, pkg.version, pkg.distro, pkg.scanned_at.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn search_cpes_by_product(&self, product: &str) -> Result<Vec<(CveRecord, CpeRecord)>, CacheError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT c.id, c.description, c.cvss_score, c.severity, c.published, c.modified,
                   p.id, p.cve_id, p.cpe_name, p.vendor, p.product,
                   p.version_start_including, p.version_end_excluding, p.version_start_excluding, p.version_end_including
            FROM cves c
            JOIN cpe p ON c.id = p.cve_id
            WHERE p.product = ?1
            "#,
        )?;
        let rows = stmt.query_map(params![product], |row| {
            Ok((
                CveRecord {
                    id: row.get(0)?,
                    description: row.get(1)?,
                    cvss_score: row.get(2)?,
                    severity: row.get(3)?,
                    published: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap(),
                    modified: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap(),
                },
                CpeRecord {
                    id: row.get(6)?,
                    cve_id: row.get(7)?,
                    cpe_name: row.get(8)?,
                    vendor: row.get(9)?,
                    product: row.get(10)?,
                    version_start_including: row.get(11)?,
                    version_end_excluding: row.get(12)?,
                    version_start_excluding: row.get(13)?,
                    version_end_including: row.get(14)?,
                },
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}
