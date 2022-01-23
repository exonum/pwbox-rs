#![no_std]
#![allow(clippy::unused_unit)]
extern crate alloc;

use rand_core::{CryptoRng, RngCore};
use wasm_bindgen::prelude::*;

use alloc::{boxed::Box, string::ToString};

use pwbox::{pure::PureCrypto, ErasedPwBox, Eraser, Suite};

// Binding to a JavaScript CSPRNG.

#[wasm_bindgen]
extern "C" {
    pub type Rng;

    #[wasm_bindgen(structural, method, js_name = "fillBytes")]
    fn random_bytes(this: &Rng, dest: &mut [u8]);
}

/// RNG based on `crypto.randomBytes()`.
struct CallbackRng(Rng);

impl RngCore for CallbackRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.0.random_bytes(&mut bytes);
        bytes
            .iter()
            .enumerate()
            .fold(0, |acc, (i, &byte)| acc + (u32::from(byte) << (i * 8)))
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.0.random_bytes(&mut bytes);
        bytes
            .iter()
            .enumerate()
            .fold(0, |acc, (i, &byte)| acc + (u64::from(byte) << (i * 8)))
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.random_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CallbackRng {}

/// Passphrase encryption utilities.
#[wasm_bindgen]
pub struct Pwbox {
    rng: CallbackRng,
}

#[wasm_bindgen]
impl Pwbox {
    /// Initializes utils with the provided RNG.
    ///
    /// `{ fillBytes: crypto.randomFillSync }` should be passed to the constructor in Node,
    /// and `{ fillBytes: crypto.getRandomValues }` in browsers.
    #[wasm_bindgen(constructor)]
    pub fn new(rng: Rng) -> Self {
        Self {
            rng: CallbackRng(rng),
        }
    }

    /// Encrypts `data` using a provided `passphrase`.
    pub fn encrypt(&mut self, passphrase: &str, data: &[u8]) -> JsValue {
        let pwbox = PureCrypto::build_box(&mut self.rng)
            .seal(passphrase, data)
            .unwrap();
        let mut eraser = Eraser::new();
        eraser.add_suite::<PureCrypto>();
        let pwbox = eraser.erase(&pwbox).unwrap();
        JsValue::from_serde(&pwbox).unwrap()
    }

    /// Decrypts encrypted box using the provided `passphrase`.
    pub fn decrypt(&self, passphrase: &str, encryption: &JsValue) -> Result<Box<[u8]>, JsValue> {
        let encryption: ErasedPwBox = encryption.into_serde().map_err(convert_err)?;
        let mut eraser = Eraser::new();
        eraser.add_suite::<PureCrypto>();
        let plaintext = eraser
            .restore(&encryption)
            .map_err(convert_err)?
            .open(passphrase)
            .map_err(convert_err)?;
        Ok(plaintext.to_vec().into_boxed_slice())
    }
}

fn convert_err<E: ToString>(error: E) -> JsValue {
    JsValue::from_str(&error.to_string())
}
