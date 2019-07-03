// Copyright 2018 The Exonum Team
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

//! Crypto primitives based on `libsodium`.

use exonum_sodiumoxide::crypto::{
    pwhash::{
        self, derive_key, MemLimit, OpsLimit, Salt, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE,
        OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE,
    },
    secretbox::{self, open_detached, seal_detached, Key, Nonce, Tag},
};
use failure::Fail;
use serde_derive::*;

use super::{Cipher, CipherOutput, DeriveKey, Eraser, Suite};

/// `Scrypt` key derivation function parameterized as per libsodium, i.e., via
/// `opslimit` (computational hardness) and `memlimit` (RAM consumption).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Scrypt {
    /// Parameter determining the computational hardness of the KDF.
    ///
    /// The default value is `1 << 19`.
    pub opslimit: u32,

    /// Parameter determining the RAM consumption of the KDF. The value is approximately
    /// equal to RAM volume in bytes, so, for example, the default value means memory consumption
    /// ~16 MB.
    ///
    /// The default value is `1 << 24`.
    pub memlimit: u32,
}

impl Default for Scrypt {
    /// Returns the "interactive" `scrypt` parameters as defined in libsodium.
    fn default() -> Self {
        Self::interactive()
    }
}

impl Scrypt {
    /// Returns the "interactive" `scrypt` parameters as defined in libsodium.
    pub const fn interactive() -> Self {
        Scrypt {
            opslimit: OPSLIMIT_INTERACTIVE.0 as u32,
            memlimit: MEMLIMIT_INTERACTIVE.0 as u32,
        }
    }

    /// Returns "light" `scrypt` parameters as used in Ethereum keystore implementations.
    pub const fn light() -> Self {
        Scrypt {
            opslimit: 3 << 18,
            memlimit: 1 << 22,
        }
    }

    /// Returns the "sensitive" `scrypt` parameters as defined in libsodium.
    pub const fn sensitive() -> Self {
        Scrypt {
            opslimit: OPSLIMIT_SENSITIVE.0 as u32,
            memlimit: MEMLIMIT_SENSITIVE.0 as u32,
        }
    }
}

#[derive(Debug, Fail)]
#[fail(display = "out of memory")]
struct ScryptError;

impl DeriveKey for Scrypt {
    fn salt_len(&self) -> usize {
        pwhash::SALTBYTES
    }

    fn derive_key(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
    ) -> Result<(), Box<dyn Fail>> {
        derive_key(
            buf,
            password,
            &Salt::from_slice(salt).expect("invalid salt length"),
            OpsLimit(self.opslimit as usize),
            MemLimit(self.memlimit as usize),
        )
        .map(drop)
        .map_err(|()| Box::new(ScryptError) as Box<dyn Fail>)
    }
}

/// `xsalsa20` symmetric cipher with `poly1305` MAC.
#[derive(Debug, Clone, Copy, Default)]
pub struct XSalsa20Poly1305;

impl Cipher for XSalsa20Poly1305 {
    const KEY_LEN: usize = secretbox::KEYBYTES;
    const NONCE_LEN: usize = secretbox::NONCEBYTES;
    const MAC_LEN: usize = secretbox::MACBYTES;

    fn seal(message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        let nonce = Nonce::from_slice(nonce).expect("nonce");
        let key = Key::from_slice(key).expect("key");
        let mut message = message.to_vec();

        let Tag(mac) = seal_detached(&mut message, &nonce, &key);
        CipherOutput {
            ciphertext: message,
            mac: mac.to_vec(),
        }
    }

    fn open(output: &mut [u8], enc: &CipherOutput, nonce: &[u8], key: &[u8]) -> Result<(), ()> {
        let nonce = Nonce::from_slice(nonce).expect("invalid nonce length");
        let key = Key::from_slice(key).expect("invalid key length");
        let mac = Tag::from_slice(&enc.mac).expect("invalid MAC length");

        output.copy_from_slice(&enc.ciphertext);
        open_detached(output, &mac, &nonce, &key)
    }
}

/// Suite for password-based encryption provided by `libsodium`.
///
/// # Ciphers
///
/// - `xsalsa20-poly1305`: XSalsa20 stream cipher with Poly1305 MAC
///
/// # KDFs
///
/// - `scrypt-nacl`: `scrypt` KDF with the `libsodium` parametrization.
///
/// # Examples
///
/// See crate-level docs for the example of usage.
#[derive(Debug)]
pub enum Sodium {}

impl Suite for Sodium {
    type Cipher = XSalsa20Poly1305;
    type DeriveKey = Scrypt;

    fn add_ciphers_and_kdfs(eraser: &mut Eraser) {
        eraser
            .add_kdf::<Scrypt>("scrypt-nacl")
            .add_cipher::<XSalsa20Poly1305>("xsalsa20-poly1305");
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        erased::test_kdf_and_cipher_corruption,
        sodium::{Scrypt, XSalsa20Poly1305},
        test_kdf_and_cipher,
    };

    #[test]
    fn scrypt_and_salsa() {
        let scrypt = Scrypt::light();
        test_kdf_and_cipher::<_, XSalsa20Poly1305>(scrypt);
    }

    #[test]
    fn scrypt_and_salsa_corruption() {
        let scrypt = Scrypt::light();
        test_kdf_and_cipher_corruption::<_, XSalsa20Poly1305>(scrypt);
    }
}
