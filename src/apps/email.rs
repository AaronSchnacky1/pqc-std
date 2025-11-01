use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::rngs::OsRng;
use rand_core::RngCore;
use crate::{kem::KyberKem, CipherText, Nonce as PqNonce, CryptoError, sig::DilithiumSig};

pub struct KyberEmail {
    kem: KyberKem,
    sig: DilithiumSig,
}

impl KyberEmail {
    pub fn new() -> Self {
        Self {
            kem: KyberKem::new(),
            sig: DilithiumSig::new(),
        }
    }

    pub fn generate_keypair(&self) -> (crate::PublicKey, crate::SecretKey) {
        self.kem.generate_keypair()
    }

    pub fn encrypt_and_sign(
        &self,
        public_key: &[u8],
        message: &[u8],
    ) -> Result<(CipherText, Vec<u8>, PqNonce, crate::Signature), CryptoError> {
        let (ciphertext, shared_secret) = self.kem.encapsulate(public_key)?;
        let key = <Aes256Gcm as KeyInit>::new((&shared_secret[..32]).into());

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = key.encrypt(nonce, message)?;

        // Sign with a fresh keypair (in real code you would use a long-term signing key)
        let (_my_pk, my_sk) = self.kem.generate_keypair();
        let sig = self.sig.sign(&my_sk, &encrypted);

        Ok((ciphertext, encrypted, nonce_bytes.to_vec(), sig))
    }

    pub fn verify_and_decrypt(
        &self,
        ciphertext: &[u8],
        encrypted: &[u8],
        secret_key: &[u8],
        nonce: &[u8],
        sig: &[u8],
        sender_pk: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        DilithiumSig::new().verify(sender_pk, encrypted, sig)?;
        let shared_secret = self.kem.decapsulate(ciphertext, secret_key)?;
        let key = <Aes256Gcm as KeyInit>::new((&shared_secret[..32]).into());
        let decryption_nonce = Nonce::from_slice(nonce);
        let decrypted = key.decrypt(decryption_nonce, encrypted)?;
        Ok(decrypted)
    }
}