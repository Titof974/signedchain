use std::fmt::{self, Result};

use crate::{block::Block, key_manager::KeyManager};

/// Represents a chain of proof of signature blocks
pub struct Chain {
    /// A chain is a list of blocks
    blocks: Vec<Block>,
}

impl Chain {
    /// Returns an empty chain
    pub fn new() -> Chain {
        Chain { blocks: Vec::new() }
    }

    /// Add a new block to the chain
    /// 
    /// # Examples
    /// 
    /// ```
    /// let key_manager = ...; // KeyManager instance
    /// let mut chain = Chain::new();
    /// chain.add_block("random data", key_manager.clone());
    /// ```
    pub fn add_block(&mut self, data: &str, key_manager: KeyManager) {
        let chain_block = self.blocks.len();
        let mut previous_hash = "";
        if chain_block != 0 {
            previous_hash = &self.blocks.get(chain_block - 1).unwrap().metadata.hash;
        }
        let block = Block::new(
            self.blocks.len().try_into().unwrap(),
            previous_hash,
            key_manager,
            data,
        );
        self.blocks.push(block);
    }

    /// Verify all block signatures in the chain with a list of keys
    /// 
    /// # Examples
    /// 
    /// ```
    /// let keys = vec![km1, km2, km3]; // List of KeyManager instances
    /// let mut chain = Chain::new();
    /// chain.add_block("random data", km1);
    /// chain.add_block("random data 2", km2);
    /// 
    /// chain.verify_with_keys(keys).unwrap();
    /// ```
    pub fn verify_with_keys(&self, keys: Vec<KeyManager>) -> Result {
        #[allow(clippy::never_loop)]
        for block in self.blocks.iter() {
            let mut trusted = false;
            for key in keys.iter() {
                match block.verify_signature(key.clone()) {
                    Ok(()) => {
                        trusted = true;
                        break;
                    }
                    Err(_err) => (),
                }
            }
            if !trusted {
                panic!("Can't verify signature of block {}", block.metadata.to_json());
            }
        }
        Ok(())
    }

    /// Verify all block hashes in the chain
    /// 
    /// # Examples
    /// 
    /// ```
    /// let km1 = KeyManager::generate();
    /// let km2 = KeyManager::generate();
    /// let mut chain = Chain::new();
    /// chain.add_block("random data", km1);
    /// chain.add_block("random data2", km2);
    /// 
    /// chain.verify_with_hashes(keys).unwrap();
    /// ```
    pub fn verify_with_hashes(&self) -> Result {
        #[allow(clippy::never_loop)]
        for block in self.blocks.iter() {
            match block.verify_hash() {
                Ok(()) => {}
                Err(err) => panic!("{}", err),
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_chain = String::new();
        debug_chain.push_str("!! Debug chain !!");
        for block in self.blocks.iter() {
            debug_chain.push_str(&format!("\nblock: {:?}", block.metadata.to_json()));
        }
        write!(f, "{}", debug_chain)
    }
}
