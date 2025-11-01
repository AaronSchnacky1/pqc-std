pub mod kem;
pub mod sig;
pub mod apps;
pub mod utils;

pub type PublicKey    = Vec<u8>;
pub type SecretKey    = Vec<u8>;
pub type CipherText   = Vec<u8>;
pub type SharedSecret = Vec<u8>;
pub type Signature    = Vec<u8>;
pub type Nonce        = Vec<u8>;

pub use kem::KyberKem;
pub use sig::DilithiumSig; // <-- only this

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("KEM error: {0}")]
    Kem(String),
    #[error("Signature error: {0}")]
    Sig(String),
    #[error("AES-GCM error: {0}")]
    AesGcm(String),
    #[error("IO error: {0}")]
    Io(std::io::Error),
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(e: aes_gcm::Error) -> Self { CryptoError::AesGcm(e.to_string()) }
}
impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self { CryptoError::Io(e) }
}