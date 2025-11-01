use crate::CryptoError;
use std::fs;

pub fn load_key(path: &str) -> Result<Vec<u8>, CryptoError> {
    Ok(fs::read(path)?)
}

pub fn save_key(path: &str, key: &[u8]) -> Result<(), CryptoError> {
    Ok(fs::write(path, key)?)
}