//! Simple example illustrating shared key negotiation.
//!
//! Run:
//!   cargo run --example basic --features mceliece348864
//! Or:
//!   ./scripts/run_example.sh basic mceliece348864

use classic_mceliece_rust::{decapsulate, encapsulate, keypair};
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

use rand::thread_rng;

use std::fs::File;
use std::io::{Read, Write};

#[no_mangle]
pub extern "C" fn getauxval(_type: usize) -> usize {
    // For AT_HWCAP, you may want to return flags like:
    // - 1 << 12 for NEON (on ARM)
    // - 1 << 13 for VFPv4

    // You can inspect `_type` and return different values if needed:
    // const AT_HWCAP: usize = 16;
    // match _type {
    //     AT_HWCAP => 1 << 12, // NEON
    //     _ => 0,
    // }

    0 // Generic safe fallback: no hardware features advertised
}

fn main() {
    let mut rng = thread_rng();

    // key generation
    let mut pubkey_buf = [0u8; CRYPTO_PUBLICKEYBYTES]; // WARN: public keys are large - optionally use Box::new()!
    let mut secret_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    println!("[Alice]\tRunning key generation …");
    let (public_key, secret_key) = keypair(&mut pubkey_buf, &mut secret_buf, &mut rng);
    println!(
        "[Alice]\tI generated public key {}",
        hex::encode_upper(public_key.as_ref())
    );
    println!(
        "[Alice]\tI generated secret key {}",
        hex::encode_upper(secret_key.as_ref())
    );

    // encapsulation
    let mut shared_secret_bob_buf = [0u8; CRYPTO_BYTES];
    println!("[Bob]\tRunning encapsulation …");
    let (ciphertext, shared_secret_bob) =
        encapsulate(&public_key, &mut shared_secret_bob_buf, &mut rng);
    println!(
        "[Bob]\tI generated shared key {}",
        hex::encode_upper(shared_secret_bob.as_ref())
    );
    println!(
        "[Bob]\tI generated ciphertext {}",
        hex::encode_upper(ciphertext.as_ref())
    );

    // decapsulation
    let mut shared_secret_alice_buf = [0u8; CRYPTO_BYTES];
    let shared_secret_alice = decapsulate(&ciphertext, &secret_key, &mut shared_secret_alice_buf);
    println!("[Alice]\tRunning decapsulation …");
    println!(
        "[Alice]\tI decapsulated shared key {}",
        hex::encode_upper(shared_secret_alice.as_ref())
    );

    if shared_secret_bob.as_array() != shared_secret_alice.as_array() {
        eprintln!("\nError: Bob's and Alice's shared key seem to differ.")
    }
}
