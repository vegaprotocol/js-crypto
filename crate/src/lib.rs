use argon2::Argon2;
pub use ed25519_compact::*;
use tiny_keccak::{Hasher, Sha3};
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use lol_alloc::{AssumeSingleThreaded, FreeListAllocator};

// SAFETY: This application is single threaded, so using AssumeSingleThreaded is allowed.
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: AssumeSingleThreaded<FreeListAllocator> =
    unsafe { AssumeSingleThreaded::new(FreeListAllocator::new()) };

#[wasm_bindgen]
pub fn ed25519_keypair_from_seed(seed_bytes: &[u8]) -> Box<[u8]> {
    let seed = Seed::from_slice(seed_bytes).unwrap();
    let kp = KeyPair::from_seed(seed);

    Box::new(*kp)
}

#[wasm_bindgen]
pub fn ed25519_sign(digest: &[u8], secret_key: &[u8]) -> Box<[u8]> {
    let _secret_key = SecretKey::from_slice(secret_key).unwrap();
    let sig = _secret_key.sign(digest, Option::None);

    Box::new(*sig)
}

#[wasm_bindgen]
pub fn ed25519_verify(signature: &[u8], digest: &[u8], public_key: &[u8]) -> bool {
    let _public_key = PublicKey::from_slice(public_key).unwrap();
    let _signature = Signature::from_slice(signature).unwrap();

    match _public_key.verify(digest, &_signature) {
        Ok(()) => true,
        Err(_) => false,
    }
}

#[wasm_bindgen]
pub fn sha3r24_pow_hash(block_hash: &[u8], tid: &[u8], nonce: u64) -> Box<[u8]> {
    let mut sha3 = Sha3::v256();
    let mut digest = [0u8; 32];
    sha3.update(b"Vega_SPAM_PoW");
    sha3.update(block_hash);
    sha3.update(tid);
    sha3.update(&nonce.to_be_bytes());
    sha3.finalize(&mut digest);

    Box::new(digest)
}

#[wasm_bindgen]
pub fn sha3r24_pow_solve(
    difficulty: u32,
    block_hash: &[u8],
    tid: &[u8],
    start_nonce: u64,
    end_nonce: u64,
) -> Option<u64> {
    let mut nonce: u64 = start_nonce;

    loop {
        if nonce >= end_nonce {
            return None;
        }

        let digest = sha3r24_pow_hash(block_hash, tid, nonce);

        let x = u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ]);

        if x.leading_zeros() >= difficulty {
            return Some(nonce);
        }

        nonce += 1;
    }
}

#[wasm_bindgen]
pub fn sha3_256_hash(message: &[u8]) -> Box<[u8]> {
    let mut sha3 = Sha3::v256();
    let mut digest = [0u8; 32];
    sha3.update(message);
    sha3.finalize(&mut digest);

    Box::new(digest)
}

#[wasm_bindgen]
pub fn argon2id_kdf(passphrase: &[u8], salt: &[u8], iterations: u32, mem: u32) -> Box<[u8]> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(mem, iterations, 1, None).unwrap(),
    );
    let mut output = [0u8; 32];

    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .unwrap();

    Box::new(output)
}
