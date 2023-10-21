use std::fmt;

use serde_json::json;
use sha256::digest;

pub struct BlockMetadata {
    pub id: i32,
    pub date: u64,
    pub previous_hash: String,
    pub hash_key: String,
    pub hash: String,
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
            hash: BlockMetadata::_generate_hash(id, date, previous_hash, hash_key, data),
        }
    }

    pub fn generate_hash(&self, data: &str) -> String {
        BlockMetadata::_generate_hash(self.id, self.date, &self.previous_hash, &self.hash_key, data)
    }

    fn _generate_hash(
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
