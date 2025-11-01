use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey as PkTrait, SecretKey as SkTrait,
                           SharedSecret as SsTrait, Ciphertext as CtTrait};
use crate::{PublicKey, SecretKey, SharedSecret, CipherText, CryptoError};

pub struct KyberKem;

impl KyberKem {
    pub fn new() -> Self { Self }

    pub fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        let (pk, sk) = keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    pub fn encapsulate(&self, pk: &[u8]) -> Result<(CipherText, SharedSecret), CryptoError> {
        let pk_ref = PkTrait::from_bytes(pk).map_err(|e| CryptoError::Kem(e.to_string()))?;
        let (ct, ss) = encapsulate(&pk_ref);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    pub fn decapsulate(&self, ct: &[u8], sk: &[u8]) -> Result<SharedSecret, CryptoError> {
        let ct_ref = CtTrait::from_bytes(ct).map_err(|e| CryptoError::Kem(e.to_string()))?;
        let sk_ref = SkTrait::from_bytes(sk).map_err(|e| CryptoError::Kem(e.to_string()))?;
        let ss = decapsulate(&ct_ref, &sk_ref);
        Ok(ss.as_bytes().to_vec())
    }
}