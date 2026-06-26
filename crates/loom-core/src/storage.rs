use rusqlite::{params, Connection, Error as SqliteError};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] SqliteError),
    #[error("Identity already exists")]
    IdentityExists,
    #[error("State not found")]
    NotFound,
}

pub struct MessageRecord {
    pub id: String,
    pub peer_key: [u8; 32],
    pub sender_key: [u8; 32],
    pub recipient_key: [u8; 32],
    pub content: String,
    pub timestamp: i64,
    pub is_read: bool,
}

pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        let storage = Self { conn: Mutex::new(conn) };
        storage.init_db()?;
        Ok(storage)
    }

    fn init_db(&self) -> Result<(), StorageError> {
        let c = self.conn.lock().unwrap();
        
        c.execute(
            "CREATE TABLE IF NOT EXISTS self_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                master_seed BLOB NOT NULL
            );",
            [],
        )?;

        c.execute(
            "CREATE TABLE IF NOT EXISTS contacts (
                public_key BLOB PRIMARY KEY,
                dh_key BLOB NOT NULL,
                display_name TEXT NOT NULL,
                added_at INTEGER NOT NULL
            );",
            [],
        )?;

        c.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                peer_key BLOB NOT NULL,
                sender_key BLOB NOT NULL,
                recipient_key BLOB NOT NULL,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                is_read INTEGER NOT NULL
            );",
            [],
        )?;

        c.execute(
            "CREATE TABLE IF NOT EXISTS ratchet_states (
                peer_public_key BLOB PRIMARY KEY,
                state BLOB NOT NULL
            );",
            [],
        )?;

        Ok(())
    }

    pub fn get_self_seed(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT master_seed FROM self_identity WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        
        if let Some(row) = rows.next()? {
            let seed_bytes: Vec<u8> = row.get(0)?;
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            Ok(Some(seed))
        } else {
            Ok(None)
        }
    }

    pub fn set_self_seed(&self, seed: &[u8; 32]) -> Result<(), StorageError> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO self_identity (id, master_seed) VALUES (1, ?1)",
            params![seed.to_vec()],
        )?;
        Ok(())
    }

    pub fn add_contact(&self, public_key: &[u8; 32], dh_key: &[u8; 32], display_name: &str) -> Result<(), StorageError> {
        let c = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        c.execute(
            "INSERT OR REPLACE INTO contacts (public_key, dh_key, display_name, added_at) VALUES (?1, ?2, ?3, ?4)",
            params![public_key.to_vec(), dh_key.to_vec(), display_name, now],
        )?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<(Vec<u8>, String)>, StorageError> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT public_key, display_name FROM contacts ORDER BY added_at DESC")?;
        let rows = stmt.query_map([], |row| {
            let key: Vec<u8> = row.get(0)?;
            let name: String = row.get(1)?;
            Ok((key, name))
        })?;

        let mut contacts = Vec::new();
        for contact in rows {
            contacts.push(contact?);
        }
        Ok(contacts)
    }

    pub fn save_message(
        &self,
        id: &str,
        peer_key: &[u8; 32],
        sender_key: &[u8; 32],
        recipient_key: &[u8; 32],
        content: &str,
        timestamp: i64,
        is_read: bool,
    ) -> Result<(), StorageError> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO messages (id, peer_key, sender_key, recipient_key, content, timestamp, is_read)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                peer_key.to_vec(),
                sender_key.to_vec(),
                recipient_key.to_vec(),
                content,
                timestamp,
                if is_read { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn get_messages(&self, peer_key: &[u8; 32]) -> Result<Vec<MessageRecord>, StorageError> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT id, peer_key, sender_key, recipient_key, content, timestamp, is_read 
             FROM messages WHERE peer_key = ?1 ORDER BY timestamp ASC"
        )?;
        let rows = stmt.query_map(params![peer_key.to_vec()], |row| {
            let id: String = row.get(0)?;
            let peer_bytes: Vec<u8> = row.get(1)?;
            let sender_bytes: Vec<u8> = row.get(2)?;
            let recipient_bytes: Vec<u8> = row.get(3)?;
            let content: String = row.get(4)?;
            let timestamp: i64 = row.get(5)?;
            let is_read_int: i32 = row.get(6)?;

            let mut peer_key = [0u8; 32];
            let mut sender_key = [0u8; 32];
            let mut recipient_key = [0u8; 32];
            peer_key.copy_from_slice(&peer_bytes);
            sender_key.copy_from_slice(&sender_bytes);
            recipient_key.copy_from_slice(&recipient_bytes);

            Ok(MessageRecord {
                id,
                peer_key,
                sender_key,
                recipient_key,
                content,
                timestamp,
                is_read: is_read_int != 0,
            })
        })?;

        let mut messages = Vec::new();
        for msg in rows {
            messages.push(msg?);
        }
        Ok(messages)
    }

    pub fn save_ratchet_state(&self, peer_public_key: &[u8; 32], state_bytes: &[u8]) -> Result<(), StorageError> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO ratchet_states (peer_public_key, state) VALUES (?1, ?2)",
            params![peer_public_key.to_vec(), state_bytes],
        )?;
        Ok(())
    }

    pub fn get_ratchet_state(&self, peer_public_key: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT state FROM ratchet_states WHERE peer_public_key = ?1")?;
        let mut rows = stmt.query(params![peer_public_key.to_vec()])?;

        if let Some(row) = rows.next()? {
            let state_bytes: Vec<u8> = row.get(0)?;
            Ok(Some(state_bytes))
        } else {
            Ok(None)
        }
    }

    pub fn get_contact_dh_key(&self, public_key: &[u8; 32]) -> Result<Option<[u8; 32]>, StorageError> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT dh_key FROM contacts WHERE public_key = ?1")?;
        let mut rows = stmt.query(params![public_key.to_vec()])?;

        if let Some(row) = rows.next()? {
            let key_bytes: Vec<u8> = row.get(0)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    pub fn delete_contact(&self, public_key: &[u8; 32]) -> Result<(), StorageError> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "DELETE FROM contacts WHERE public_key = ?1",
            params![public_key.to_vec()],
        )?;
        c.execute(
            "DELETE FROM ratchet_states WHERE peer_public_key = ?1",
            params![public_key.to_vec()],
        )?;
        Ok(())
    }
}
