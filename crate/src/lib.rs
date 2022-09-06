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

#[wasm_bindgen]
pub fn pow_hash(block_hash: &[u8], tid: &[u8], nonce: u64) -> Box<[u8]> {
    let mut sha3 = Sha3::v256();
    let mut digest = [0u8; 32];
    sha3.update(b"Vega_SPAM_PoW");
    sha3.update(block_hash);
    sha3.update(tid);
    sha3.update(&nonce.to_be_bytes());
    sha3.finalize(&mut digest);

    return Box::new(digest);
}

#[wasm_bindgen]
pub fn pow_solve(difficulty: u32, block_hash: &[u8], tid: &[u8], start_nonce: u64) -> u64 {
    let mut nonce: u64 = start_nonce;

    loop {
        let digest = pow_hash(block_hash, tid, nonce);

        let x = u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7]
        ]);

        if x.leading_zeros() >= difficulty {
            return nonce;
        }

        nonce += 1;
    }
}

fn _hash(message: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut digest = [0u8; 32];
    sha3.update(message);
    sha3.finalize(&mut digest);
    digest
}
