use std::{fmt, time::{UNIX_EPOCH, SystemTime}};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::{digest, try_digest};

use crate::key_manager::KeyManager;

pub struct BlockMetadata {
    id: i32,
    date: u64,
    previous_hash: String,
    hash_key: String,
    hash: String,
}

impl BlockMetadata {
    pub fn new(
        id: i32,
        date: u64,
        previous_hash: &str,
        hash_key: &str,
        data: &str,
    ) -> BlockMetadata {
        BlockMetadata {
            id,
            date,
            previous_hash: String::from(previous_hash),
            hash_key: String::from(hash_key),
            hash: BlockMetadata::generate_hash(id, date, previous_hash, hash_key, data),
        }
    }

    pub fn generate_hash(
        id: i32,
        date: u64,
        previous_hash: &str,
        hash_key: &str,
        data: &str,
    ) -> String {
        let json = json!({
            "id": id,
            "date": date,
            "previous_hash": previous_hash,
            "hash_key": hash_key,
        });
        digest(serde_json::to_string(&json).unwrap() + data)
    }

    pub fn to_json(&self) -> String {
        let json = json!({
            "id": self.id,
            "date": self.date,
            "previous_hash": self.previous_hash,
            "hash_key": self.hash_key,
        });
        serde_json::to_string(&json).expect("Can't serialize metadata")
    }

}

impl fmt::Debug for BlockMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "id: {}, date: {}, previous_hash: {}, previous_signature: {}, hash: {}",
            self.id, self.date, self.previous_hash, self.hash_key, self.hash
        )
    }
}

pub struct Block {
    metadata: BlockMetadata,
    data: String,
    signature: Vec<u8>,
}

impl Block {
    pub fn new(id: i32, previous_hash: &str, key_manager: KeyManager, data: &str) -> Block {
        let metadata = BlockMetadata::new(id, SystemTime::now().duration_since(UNIX_EPOCH).expect("Can't retrieve time for generate block").as_secs(), previous_hash, key_manager.public_key_hash().as_str(), data);
        let metadata_json = metadata.to_json();
        Block {
            metadata,
            data: data.to_string(),
            signature: key_manager.sign(metadata_json.as_str()),
        }
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "metadata: {}, data: {}, signature: {:?}",
            self.metadata.to_json(), self.data, self.signature
        )
    }
}
