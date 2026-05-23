use crate::{ProtocolError, Result};
use pqc_kyber::{
    keypair as kyber_keypair,
    encapsulate as kyber_encapsulate,
    decapsulate as kyber_decapsulate,
    KYBER_PUBLICKEYBYTES, KYBER_CIPHERTEXTBYTES, KYBER_SECRETKEYBYTES,
};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

pub const KEM_PK_SIZE: usize = KYBER_PUBLICKEYBYTES;
pub const KEM_CT_SIZE: usize = KYBER_CIPHERTEXTBYTES;

pub const HYBRID_PK_SIZE: usize = KYBER_PUBLICKEYBYTES + 32;
pub const HYBRID_CT_SIZE: usize = KYBER_CIPHERTEXTBYTES + 32;

pub struct HybridKeyPair {
    pub kyber_pk: [u8; KEM_PK_SIZE],
    kyber_sk: [u8; KYBER_SECRETKEYBYTES],
    x25519_sk: StaticSecret,
    pub x25519_pk: [u8; 32],
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        self.kyber_sk.zeroize();
    }
}

pub struct HybridEncapsulation {
    pub kyber_ct: [u8; KEM_CT_SIZE],
    pub x25519_ct: [u8; 32],
    pub shared_secret: [u8; 32],
}

pub fn generate_hybrid_keypair() -> Result<HybridKeyPair> {
    let mut rng = rand_core::OsRng;
    let kyber_kp = kyber_keypair(&mut rng)
        .map_err(|e| ProtocolError::Kem(format!("{:?}", e)))?;

    let x25519_sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519_pk = PublicKey::from(&x25519_sk);

    Ok(HybridKeyPair {
        kyber_pk: kyber_kp.public,
        kyber_sk: kyber_kp.secret,
        x25519_sk,
        x25519_pk: x25519_pk.to_bytes(),
    })
}

pub fn hybrid_encapsulate(kyber_pk: &[u8], x25519_pk: &[u8; 32]) -> Result<HybridEncapsulation> {
    let mut rng = rand_core::OsRng;
    let (kyber_ct, kyber_ss) = kyber_encapsulate(kyber_pk, &mut rng)
        .map_err(|e| ProtocolError::Kem(format!("{:?}", e)))?;

    let peer_pk = PublicKey::from(*x25519_pk);
    let x25519_sk = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let x25519_ct = PublicKey::from(&x25519_sk);
    let x25519_ss = x25519_sk.diffie_hellman(&peer_pk);

    let shared_secret = combine_secrets(kyber_ss.as_slice(), x25519_ss.as_bytes());

    Ok(HybridEncapsulation {
        kyber_ct,
        x25519_ct: x25519_ct.to_bytes(),
        shared_secret,
    })
}

pub fn hybrid_decapsulate(
    keypair: &HybridKeyPair,
    kyber_ct: &[u8],
    x25519_ct: &[u8; 32],
) -> Result<[u8; 32]> {
    let kyber_ss = kyber_decapsulate(kyber_ct, &keypair.kyber_sk)
        .map_err(|e| ProtocolError::Kem(format!("{:?}", e)))?;

    let peer_pk = PublicKey::from(*x25519_ct);
    let x25519_ss = keypair.x25519_sk.diffie_hellman(&peer_pk);

    Ok(combine_secrets(kyber_ss.as_slice(), x25519_ss.as_bytes()))
}

fn combine_secrets(kyber_ss: &[u8], x25519_ss: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tundra-hybrid-kem-v1");
    hasher.update(kyber_ss);
    hasher.update(x25519_ss);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        let kp = generate_hybrid_keypair().unwrap();
        let enc = hybrid_encapsulate(&kp.kyber_pk, &kp.x25519_pk).unwrap();
        let ss = hybrid_decapsulate(&kp, &enc.kyber_ct, &enc.x25519_ct).unwrap();
        assert_eq!(enc.shared_secret, ss);
    }

    #[test]
    fn hybrid_kem_wrong_keys() {
        let kp1 = generate_hybrid_keypair().unwrap();
        let kp2 = generate_hybrid_keypair().unwrap();
        let enc = hybrid_encapsulate(&kp1.kyber_pk, &kp1.x25519_pk).unwrap();
        let ss2 = hybrid_decapsulate(&kp2, &enc.kyber_ct, &enc.x25519_ct).unwrap();
        assert_ne!(enc.shared_secret, ss2);
    }

    #[test]
    fn hybrid_deterministic_combine() {
        let s1 = combine_secrets(&[1u8; 32], &[2u8; 32]);
        let s2 = combine_secrets(&[1u8; 32], &[2u8; 32]);
        assert_eq!(s1, s2);
        let s3 = combine_secrets(&[2u8; 32], &[1u8; 32]);
        assert_ne!(s1, s3);
    }
}
