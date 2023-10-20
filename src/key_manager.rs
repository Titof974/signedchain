use rsa::sha2::{Digest, Sha256};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha256::digest;
use std::io::{Error, Write};
use std::{fs::File, io::Read};

#[derive(Clone)]
pub struct KeyManager {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl KeyManager {
    pub fn generate() -> KeyManager {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let priv_key =
            RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a private key");
        let pub_key = RsaPublicKey::from(&priv_key);
        KeyManager {
            private_key: priv_key
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
            public_key: pub_key
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
        }
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn write_private_key(&self, path: &str) {
        let _ = KeyManager::write(path, self.private_key.as_slice());
    }

    pub fn write_public_key(&self, path: &str) {
        let _ = KeyManager::write(path, self.public_key.as_slice());
    }

    pub fn from_private_key_path(path: &str) -> KeyManager {
        let mut private_key_file = File::open(path).expect("Can't open private key file");
        let mut private_key_data = String::new();
        private_key_file
            .read_to_string(&mut private_key_data)
            .expect("Error reading private key");
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_data.as_str())
            .expect("Can't load private key");
        let pub_key =
            RsaPublicKey::from(RsaPrivateKey::from_pkcs8_pem(private_key_data.as_str()).unwrap());
        KeyManager {
            private_key: private_key
                .clone()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
            public_key: pub_key
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
        }
    }

    pub fn from_private_key(private_key: &[u8]) -> KeyManager {
        let binding = String::from_utf8_lossy(private_key).to_string();
        let priv_key_str = binding.as_str();
        let priv_key = RsaPrivateKey::from_pkcs8_pem(
            priv_key_str,
        )
        .expect("Can't load private key");
        let pub_key =
            RsaPublicKey::from(RsaPrivateKey::from_pkcs8_pem(priv_key_str).unwrap());
        KeyManager {
            private_key: priv_key
                .clone()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
            public_key: pub_key
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
        }
    }

    pub fn from(private_key: &[u8], public_key: &[u8]) -> KeyManager {
        KeyManager {
            private_key: private_key.clone().to_owned(),
            public_key: public_key.clone().to_owned(),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        RsaPrivateKey::from_pkcs8_pem(
            String::from_utf8(self.private_key.clone())
                .unwrap()
                .as_str(),
        )
        .unwrap()
        .sign(
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            &Sha256::digest(data),
        )
        .expect("Can't sign data")
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) {
        RsaPublicKey::from_public_key_pem(
            String::from_utf8(self.public_key.clone()).unwrap().as_str(),
        )
        .unwrap()
        .verify(
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            &Sha256::digest(data),
            signature,
        )
        .expect("Can't verify data");
    }

    pub fn private_key_hash(&self) -> String {
        digest(String::from_utf8(self.private_key.clone()).expect("Can't parse private key"))
    }

    pub fn public_key_hash(&self) -> String {
        digest(String::from_utf8(self.public_key.clone()).expect("Can't parse public key"))
    }

    fn write(path: &str, data: &[u8]) -> Result<(), Error> {
        let mut output = File::create(path)?;
        output.write_all(data)?;
        Ok(())
    }
}
