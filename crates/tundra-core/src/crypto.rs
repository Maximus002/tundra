use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    ChaCha20Poly1305, Nonce,
};

const NONCE_SIZE: usize = 12;

pub struct Cipher {
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self { cipher }
    }

    fn random_nonce() -> Nonce {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        *Nonce::from_slice(&nonce_bytes)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = Self::random_nonce();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend(ciphertext);
        Ok(output)
    }

    pub fn decrypt(&mut self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        if blob.len() < NONCE_SIZE + 16 {
            anyhow::bail!("ciphertext too short");
        }
        let nonce = Nonce::from_slice(&blob[..NONCE_SIZE]);
        let ciphertext = &blob[NONCE_SIZE..];
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))
    }
}

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn derive_key(shared_secret: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tundra-key-derive-v2");
    hasher.update(shared_secret);
    hasher.update(context);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let mut enc = Cipher::new(&key);
        let mut dec = Cipher::new(&key);

        let plaintext = b"hello, tundra!";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        assert_ne!(plaintext.to_vec(), ciphertext);
        assert!(ciphertext.len() > NONCE_SIZE + plaintext.len());

        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn encrypt_produces_unique_ciphertexts() {
        let key = generate_key();
        let mut enc = Cipher::new(&key);
        let ct1 = enc.encrypt(b"same data").unwrap();
        let ct2 = enc.encrypt(b"same data").unwrap();
        assert_ne!(ct1, ct2, "random nonce must produce different ciphertexts");
    }

    #[test]
    fn key_derivation_deterministic() {
        let k1 = derive_key(b"secret", b"context");
        let k2 = derive_key(b"secret", b"context");
        assert_eq!(k1, k2);
        let k3 = derive_key(b"secret", b"different");
        assert_ne!(k1, k3);
    }
}
