use crate::{ProtocolError, Result};
use pqc_kyber::{
    keypair as kyber_keypair,
    encapsulate as kyber_encapsulate,
    decapsulate as kyber_decapsulate,
    KYBER_PUBLICKEYBYTES, KYBER_CIPHERTEXTBYTES, KYBER_SECRETKEYBYTES,
};

pub const KEM_PK_SIZE: usize = KYBER_PUBLICKEYBYTES;
pub const KEM_CT_SIZE: usize = KYBER_CIPHERTEXTBYTES;

pub struct KemKeyPair {
    pub public_key: [u8; KEM_PK_SIZE],
    secret: [u8; KYBER_SECRETKEYBYTES],
}

pub struct KemEncapsulation {
    pub ciphertext: [u8; KEM_CT_SIZE],
    pub shared_secret: [u8; 32],
}

pub fn generate_keypair() -> Result<KemKeyPair> {
    let mut rng = rand_core::OsRng;
    let kp = kyber_keypair(&mut rng)
        .map_err(|e| ProtocolError::Kem(format!("{:?}", e)))?;
    Ok(KemKeyPair {
        public_key: kp.public,
        secret: kp.secret,
    })
}

pub fn encapsulate(public_key: &[u8]) -> Result<KemEncapsulation> {
    let mut rng = rand_core::OsRng;
    let (ct, ss) = kyber_encapsulate(public_key, &mut rng)
        .map_err(|e| ProtocolError::Kem(format!("{:?}", e)))?;
    Ok(KemEncapsulation {
        ciphertext: ct,
        shared_secret: ss,
    })
}

pub fn decapsulate(keypair: &KemKeyPair, ciphertext: &[u8]) -> Result<[u8; 32]> {
    let ss = kyber_decapsulate(ciphertext, &keypair.secret)
        .map_err(|e| ProtocolError::Kem(format!("{:?}", e)))?;
    Ok(ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let kp = generate_keypair().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap();
        let ss = decapsulate(&kp, &enc.ciphertext).unwrap();
        assert_eq!(enc.shared_secret, ss);
    }

    #[test]
    fn kem_different_keys() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let enc = encapsulate(&kp1.public_key).unwrap();
        let ss2 = decapsulate(&kp2, &enc.ciphertext).unwrap();
        assert_ne!(enc.shared_secret, ss2);
    }
}
