// src/sig.rs
use pqcrypto_dilithium::dilithium5::{keypair, sign, open};
use pqcrypto_traits::sign::{PublicKey as SPk, SecretKey as SSk, SignedMessage as SM};
use crate::{PublicKey, SecretKey, Signature, CryptoError};

pub struct DilithiumSig;

impl DilithiumSig {
    pub fn new() -> Self { Self }

    pub fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        let (pk, sk) = keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    pub fn sign(&self, sk: &[u8], msg: &[u8]) -> Signature {
        let sk_ref = SSk::from_bytes(sk).unwrap();
        let signed = sign(msg, &sk_ref);
        signed.as_bytes().to_vec()
    }

    pub fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let pk_ref = SPk::from_bytes(pk).map_err(|e| CryptoError::Sig(e.to_string()))?;
        let sig_ref = SM::from_bytes(sig).map_err(|e| CryptoError::Sig(e.to_string()))?;

        // Use `open` and check if recovered message == original
        let recovered = open(&sig_ref, &pk_ref)
            .map_err(|e| CryptoError::Sig(e.to_string()))?;

        if recovered.as_slice() == msg {
            Ok(())
        } else {
            Err(CryptoError::Sig("signature verification failed".to_string()))
        }
    }
}