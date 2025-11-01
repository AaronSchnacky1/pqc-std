pqc-std 0.0.1

DEMO PQC Architecture DEMO NOT FOR PRODUCTION

KEM (Key Encapsulation): Kyber-1024 (NIST PQC Winner, Security Level 5)
Signature: Dilithium5 (NIST PQC Winner, Security Level 5)
Symmetric Encryption: AES-256-GCM
Installation
Add this to your Cargo.toml. Note that the default configuration relies on the Rust Standard Library (std) for convenient random number generation.

[dependencies]
pqc-std = "0.0.1"
Features
This crate is built on Rust cryptographic primitives.

no_std Compatible	Conditionally
Note on no_std: The underlying cryptographic primitives are compatible with no_std. However, the current default build uses std-dependent features for dependencies like rand and getrandom to enable convenient, secure key generation. To achieve true no_std support for a constrained environment, you will need to manage the dependencies to provide your own secure random number generator that implements rand_core::RngCore.

Quick Example
use pqc-std::apps::chat::KyberChat;

fn main() {
    let chat = KyberChat::new();
    let (pk, sk) = chat.generate_keypair();

    let msg = b"Quantum-safe hello!";
    let (ct, enc, nonce) = chat.encrypt_message(&pk, msg).unwrap();

    let decrypted = chat.decrypt_message(&ct, &enc, &sk, &nonce).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
Output:

Architectural Demo, not ##NIST
made by AI: gemini2.5flash, Grok3, foss

To be a pure, compliant PQC library, you should only implement the FIPS 203 and FIPS 204 specifications, which do not include AES-GCM. You should, however, ensure your implementations correctly use the required SHA3/SHAKE hash functions within the Kyber and Dilithium algorithms.

AES-GCM is Symmetric: AES-GCM is a symmetric-key algorithm and is considered quantum-resistant (a 256-bit key provides 128-bit quantum security against Grover's algorithm), but it is not one of the new PQC standards (FIPS 203, 204, 205).

Modules
kem::KyberKem – Key Encapsulation
sig::DilithiumSig – Digital Signatures
apps::chat::KyberChat – Encrypted chat
apps::email::KyberEmail – Sign + encrypt
apps::firmware::KyberFirmware – Firmware update
License
Licensed under MIT.
