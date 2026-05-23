use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};

const NONCE_SIZE: usize = 12;

pub const ROLE_CLIENT: u8 = 0x01;
pub const ROLE_SERVER: u8 = 0x02;

pub struct Cipher {
    cipher: ChaCha20Poly1305,
    counter: AtomicU64,
    role: u8,
}

impl Cipher {
    pub fn new_with_role(key: &[u8; 32], role: u8) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self {
            cipher,
            counter: AtomicU64::new(0),
            role,
        }
    }

    pub fn new(key: &[u8; 32]) -> Self {
        Self::new_with_role(key, 0)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
        let nonce = counter_to_nonce(ctr, self.role);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend(ciphertext);
        Ok(output)
    }

    pub fn decrypt(&self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        if blob.len() < NONCE_SIZE + 16 {
            anyhow::bail!("ciphertext too short");
        }
        let nonce = Nonce::from_slice(&blob[..NONCE_SIZE]);
        let ciphertext = &blob[NONCE_SIZE..];
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))
    }

    pub fn encrypt_count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

fn counter_to_nonce(ctr: u64, role: u8) -> Nonce {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[..8].copy_from_slice(&ctr.to_be_bytes());
    nonce_bytes[8..11].copy_from_slice(&[0u8; 3]);
    nonce_bytes[11] = role;
    *Nonce::from_slice(&nonce_bytes)
}

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use chacha20poly1305::aead::rand_core::RngCore;
    chacha20poly1305::aead::OsRng.fill_bytes(&mut key);
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

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let enc = Cipher::new(&key);
        let dec = Cipher::new(&key);

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
        let enc = Cipher::new(&key);
        let ct1 = enc.encrypt(b"same data").unwrap();
        let ct2 = enc.encrypt(b"same data").unwrap();
        assert_ne!(ct1, ct2, "counter nonce must produce different ciphertexts");
    }

    #[test]
    fn key_derivation_deterministic() {
        let k1 = derive_key(b"secret", b"context");
        let k2 = derive_key(b"secret", b"context");
        assert_eq!(k1, k2);
        let k3 = derive_key(b"secret", b"different");
        assert_ne!(k1, k3);
    }

    #[test]
    fn counter_increments() {
        let key = generate_key();
        let cipher = Cipher::new(&key);
        assert_eq!(cipher.encrypt_count(), 0);
        cipher.encrypt(b"a").unwrap();
        assert_eq!(cipher.encrypt_count(), 1);
        cipher.encrypt(b"b").unwrap();
        assert_eq!(cipher.encrypt_count(), 2);
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
    }
}
