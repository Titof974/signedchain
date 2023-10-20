use std::{fmt, time::{UNIX_EPOCH, SystemTime}};

use crate::{block_metadata::BlockMetadata, key_manager::KeyManager};


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
            signature: key_manager.sign(metadata_json.as_bytes()),
        }
    }

    pub fn verify(&self, key_manager: KeyManager) {
        let metadata_json = self.metadata.to_json();
        key_manager.verify(metadata_json.as_bytes(), &self.signature)
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
