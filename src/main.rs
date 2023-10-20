pub mod key_manager;
pub mod block;

use block::Block;
use crate::key_manager::KeyManager;
mod block_metadata;

fn main() {
    // let mut rng = rand::thread_rng();
    // let bits = 2048;
    // let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // let pub_key = RsaPublicKey::from(&priv_key);
    // println!(
    //     "Private key: {:?}",
    //     priv_key.to_pkcs8_pem(LineEnding::LF).unwrap()
    // );
    // write(&"./private_key", priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).expect("Can't write private key");
    // println!(
    //     "Public key: {:?}",
    //     RsaPublicKey::from(&priv_key)
    //         .to_public_key_pem(LineEnding::LF)
    //         .unwrap()
    // );
    // write(&"./public_key", RsaPublicKey::from(&priv_key)
    // .to_public_key_pem(LineEnding::LF)
    // .unwrap().as_bytes()).expect("Can't write public key");
    // // Encrypt
    // let data = b"hello world";
    // let enc_data = pub_key
    //     .encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])
    //     .expect("failed to encrypt");
    // println!("Encrypted data: {:?}", enc_data);
    // assert_ne!(&data[..], &enc_data[..]);

    // // Decrypt
    // let dec_data = priv_key
    //     .decrypt(Pkcs1v15Encrypt, &enc_data)
    //     .expect("failed to decrypt");
    // println!("Decrypted data: {:?}", String::from_utf8_lossy(&dec_data));
    // assert_eq!(&data[..], &dec_data[..]);


    // ------------------

    // let key = KeyManager::generate();
    // key.fingerprint();
    // key.write_private_key("./private_key");
    // key.write_public_key("./public_key");


    //--------------
    // let kkey = KeyManager::from_private_key_path("./private_key");
    // let test = BlockMetadata::new(0, 1234545, "salutosamigos",  kkey.private_key_hash().as_str(), "{}");
    
    // let s = kkey.sign("salutosamigos");
    // println!("{:?}", s);
    // kkey.verify("salutosamigos".as_bytes(), s.as_slice());

    // ---------------
    let key: KeyManager = KeyManager::generate();
    let key2 = KeyManager::generate();
    let block = Block::new(0, "", key.clone(), "{'h': 12}");
    println!("{:?}", block);
    block.verify(key2.clone());
}
