pub use ed25519_compact::*;
use tiny_keccak::{Hasher, Sha3};
use wasm_bindgen::prelude::*;

extern crate wee_alloc;

// Use `wee_alloc` as the global allocator, to reduce the WASM binary size
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn keypair_from_seed(seed_bytes: &[u8]) -> Box<[u8]> {
    let seed = Seed::from_slice(seed_bytes).unwrap();
    let kp = KeyPair::from_seed(seed);

    return Box::new(*kp);
}

#[wasm_bindgen]
pub fn sign(message: &[u8], secret_key: &[u8]) -> Box<[u8]> {
    let digest = _hash(message);
    let _secret_key = SecretKey::from_slice(secret_key).unwrap();
    let sig = _secret_key.sign(digest, Option::None);

    return Box::new(*sig);
}

#[wasm_bindgen]
pub fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let digest = _hash(message);

    let _public_key = PublicKey::from_slice(public_key).unwrap();
    let _signature = Signature::from_slice(signature).unwrap();

    return match _public_key.verify(digest, &_signature) {
        Ok(()) => true,
        Err(_) => false,
    };
}

fn _hash(message: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut digest = [0u8; 32];
    sha3.update(message);
    sha3.finalize(&mut digest);
    digest
}
