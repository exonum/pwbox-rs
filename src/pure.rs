// Copyright 2019 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pure Rust crypto primitives. Can be used if your app targets WASM or some other constrained
//! environment.

use anyhow::Error;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    ChaCha20Poly1305,
};
use scrypt::{scrypt, ScryptParams as Params};
use serde::{Deserialize, Serialize};

use crate::{alloc::Vec, Cipher, CipherOutput, DeriveKey, Eraser, ScryptParams, Suite};

impl Cipher for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const MAC_LEN: usize = 16;

    fn seal(message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        let mut buffer = Self::new(GenericArray::clone_from_slice(key))
            .encrypt(GenericArray::from_slice(nonce), message)
            .expect("Cannot encrypt with ChaCha20Poly1305");
        assert!(
            buffer.len() > Self::MAC_LEN,
            "Insufficient ciphertext length"
        );
        let mac = buffer.split_off(buffer.len() - Self::MAC_LEN);
        CipherOutput {
            ciphertext: buffer,
            mac,
        }
    }

    fn open(
        output: &mut [u8],
        encrypted: &CipherOutput,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<(), ()> {
        let mut encryption = Vec::with_capacity(encrypted.ciphertext.len() + Self::MAC_LEN);
        encryption.extend_from_slice(&encrypted.ciphertext);
        encryption.extend_from_slice(&encrypted.mac);

        Self::new(GenericArray::clone_from_slice(key))
            .decrypt(GenericArray::from_slice(nonce), &*encryption)
            .map(|plaintext| {
                output.copy_from_slice(&plaintext);
            })
            .map_err(drop)
    }
}

/// Pure Rust wrapper around scrypt.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scrypt(pub ScryptParams);

impl DeriveKey for Scrypt {
    fn salt_len(&self) -> usize {
        32
    }

    #[cfg(feature = "std")]
    fn derive_key(&self, buf: &mut [u8], password: &[u8], salt: &[u8]) -> Result<(), Error> {
        let params = Params::new(self.0.log_n, self.0.r, self.0.p)?;
        scrypt(password, salt, &params, buf).map_err(Error::new)
    }

    #[cfg(not(feature = "std"))]
    fn derive_key(&self, buf: &mut [u8], password: &[u8], salt: &[u8]) -> Result<(), Error> {
        // Without `std`, we need to use more dumb conversions to `anyhow::Error`.
        let params = Params::new(self.0.log_n, self.0.r, self.0.p).map_err(Error::msg)?;
        scrypt(password, salt, &params, buf).map_err(Error::msg)
    }
}

/// Suite for password-based encryption provided by pure-Rust crypto primitives.
///
/// # Ciphers
///
/// - `chacha20-poly1305`: ChaCha20 stream cipher with Poly1305 MAC
///
/// # KDFs
///
/// - `scrypt`: `scrypt` KDF with the original paper parametrization.
///
/// # Examples
///
/// This suite can be used in constrained environments, e.g., WASM.
///
/// ```
/// use rand::thread_rng;
/// use pwbox::{Eraser, ErasedPwBox, Suite, pure::PureCrypto};
/// # use pwbox::{Error, pure::Scrypt, ScryptParams};
///
/// # fn main() -> Result<(), Error> {
/// // Create a new box.
/// let pwbox = PureCrypto::build_box(&mut thread_rng())
/// #   .kdf(Scrypt(ScryptParams::custom(2, 1)))
///     .seal(b"correct horse", b"battery staple")
///     .unwrap();
///
/// // Read from existing box.
/// let mut eraser = Eraser::new();
/// eraser.add_suite::<PureCrypto>();
/// let erased: ErasedPwBox = // deserialized from some format
/// #   eraser.erase(&pwbox).unwrap();
/// let plaintext = eraser.restore(&erased)?.open(b"correct horse")?;
/// # assert_eq!(&*plaintext, b"battery staple");
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum PureCrypto {}

impl Suite for PureCrypto {
    type Cipher = ChaCha20Poly1305;
    type DeriveKey = Scrypt;

    fn add_ciphers_and_kdfs(eraser: &mut Eraser) {
        eraser
            .add_kdf::<Scrypt>("scrypt")
            .add_cipher::<ChaCha20Poly1305>("chacha20-poly1305");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{erased::test_kdf_and_cipher_corruption, test_kdf_and_cipher};
    use rand::{thread_rng, Rng};

    #[test]
    fn chacha_roundtrip() {
        let nonce = [0; ChaCha20Poly1305::NONCE_LEN];
        let mut rng = thread_rng();
        let key: [u8; ChaCha20Poly1305::KEY_LEN] = rng.gen();
        let mut encrypted = ChaCha20Poly1305::seal(b"Foobar", &nonce, &key);
        assert_eq!(encrypted.ciphertext.len(), 6);
        let mut decrypted = [0_u8; 6];
        ChaCha20Poly1305::open(&mut decrypted, &encrypted, &nonce, &key).unwrap();
        assert_eq!(decrypted, *b"Foobar");

        // Maul the MAC.
        encrypted.mac[11] ^= 1;
        assert!(ChaCha20Poly1305::open(&mut decrypted, &encrypted, &nonce, &key).is_err());
        encrypted.mac[11] ^= 1;

        // Maul the ciphertext.
        encrypted.ciphertext[2] ^= 16;
        assert!(ChaCha20Poly1305::open(&mut decrypted, &encrypted, &nonce, &key).is_err());
    }

    #[test]
    fn scrypt_and_chacha() {
        let scrypt = Scrypt(ScryptParams::light());
        test_kdf_and_cipher::<_, ChaCha20Poly1305>(scrypt);
    }

    #[test]
    fn scrypt_and_chacha_corruption() {
        let scrypt = Scrypt(ScryptParams::light());
        test_kdf_and_cipher_corruption::<_, ChaCha20Poly1305>(scrypt);
    }

    #[test]
    #[cfg(feature = "exonum_sodiumoxide")]
    fn compatibility_with_sodium() {
        use crate::sodium::Sodium;

        let encrypted = PureCrypto::build_box(&mut thread_rng())
            .kdf(Scrypt(ScryptParams::light()))
            .seal(b"correct horse", b"battery staple")
            .unwrap();
        let mut eraser = Eraser::new();
        eraser.add_suite::<PureCrypto>();
        let encrypted = eraser.erase(&encrypted).unwrap();

        let mut eraser = Eraser::new();
        eraser.add_suite::<Sodium>();
        let encrypted = eraser.restore(&encrypted).unwrap();
        assert_eq!(
            encrypted.open(b"correct horse").unwrap().as_ref(),
            b"battery staple"
        );
    }
}
