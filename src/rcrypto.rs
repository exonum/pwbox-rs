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

//! `rust-crypto` cryptographic backend.

use clear_on_drop::ClearOnDrop;
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes, aes_gcm,
    digest::Digest,
    scrypt::{scrypt, ScryptParams},
    sha3::Sha3,
};
use failure::Fail;
use serde_derive::*;

use crate::utils::log_transform::LogNTransform;
use crate::{
    Cipher, CipherOutput, CipherWithMac, DeriveKey, Eraser, Mac, Suite, UnauthenticatedCipher,
};

/// AES-128 cipher in CTR mode.
///
/// This cipher is used as a part of Ethereum keystores. Note that as this cipher
/// is not authenticated, it should be paired with a MAC construction (e.g., `Keccak256`)
/// in order to create a `Cipher`.
#[derive(Debug)]
pub enum Aes128Ctr {}

impl UnauthenticatedCipher for Aes128Ctr {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 16;

    fn seal_or_open(message: &mut [u8], nonce: &[u8], key: &[u8]) {
        let mut output = vec![0; message.len()];
        let mut output = ClearOnDrop::new(&mut output);
        aes::ctr(aes::KeySize::KeySize128, key, nonce).process(message, &mut *output);
        message.copy_from_slice(&output);
    }
}

/// MAC construction based on Keccak256 hash function.
///
/// This MAC is used as a part of Ethereum keystores.
///
/// # Specification
///
/// ```text
/// Mac(key, message) = Keccak256(key || message)
/// ```
///
/// where `||` denotes concatenation of byte arrays.
///
/// # Theoretical note
///
/// This construction is only secure because hash functions from Keccak/SHA-3 family
/// are resistant to [length extension] attacks. Implementing a similar construction based
/// on functions from the SHA-2 family or other hash functions susceptible to length extension
/// attacks is **not secure**; use an [HMAC] instead.
///
/// [length extension]: https://en.wikipedia.org/wiki/Length_extension_attack
/// [HMAC]: https://en.wikipedia.org/wiki/HMAC
#[derive(Debug)]
pub enum Keccak256 {}

impl Mac for Keccak256 {
    const KEY_LEN: usize = 16;
    const MAC_LEN: usize = 32;

    fn digest(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3::keccak256();
        hasher.input(key);
        hasher.input(message);
        let mut output = vec![0_u8; Self::MAC_LEN];
        hasher.result(&mut output);
        output
    }
}

/// `Scrypt` key derivation function parameterized as per the original paper.
///
/// # Serialization
///
/// The function is serialized as three fields: `n`, `r` and `p`. See the [Scrypt paper]
/// for more details on what they mean.
///
/// ```
/// use serde_json::json;
/// # use pwbox::rcrypto::Scrypt;
///
/// let scrypt = Scrypt::default();
/// assert_eq!(
///     serde_json::to_value(scrypt).unwrap(),
///     json!({ "n": 262144, "r": 8, "p": 1 })
/// );
/// ```
///
/// [Scrypt paper]: http://www.tarsnap.com/scrypt/scrypt.pdf
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Scrypt {
    #[serde(rename = "n", with = "LogNTransform")]
    log_n: u8,
    r: u32,
    p: u32,
}

impl Default for Scrypt {
    /// Returns the "interactive" `scrypt` parameters as defined in libsodium.
    ///
    /// ```text
    /// n = 2^18, r = 8, p = 1.
    /// ```
    fn default() -> Self {
        Scrypt {
            log_n: 18,
            r: 8,
            p: 1,
        }
    }
}

impl Scrypt {
    /// Returns "light" `scrypt` parameters as used in Ethereum keystore implementations.
    ///
    /// ```text
    /// n = 2^12, r = 8, p = 6.
    /// ```
    pub const fn light() -> Self {
        Scrypt {
            log_n: 12,
            r: 8,
            p: 6,
        }
    }

    /// Creates custom parameters for scrypt KDF.
    ///
    /// The `r` parameter is always set to 8 as per libsodium conversion
    /// from `opslimit` / `memlimit` and per Ethereum keystore implementations.
    pub const fn custom(log_n: u8, p: u32) -> Self {
        Scrypt { log_n, p, r: 8 }
    }
}

impl DeriveKey for Scrypt {
    fn salt_len(&self) -> usize {
        32
    }

    fn derive_key(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
    ) -> Result<(), Box<dyn Fail>> {
        let params = ScryptParams::new(self.log_n, self.r, self.p);
        scrypt(password, salt, &params, buf);
        Ok(())
    }
}

/// AES-128 cipher in GCM mode.
///
/// # Implementation note
///
/// The GCM mode allows authenticating public data in addition to the ciphertext;
/// for this application, this additional data is an empty slice `&[]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes128Gcm;

impl Cipher for Aes128Gcm {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 12;
    const MAC_LEN: usize = 16;

    fn seal(message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        // We don't use additional data (the last parameter to the constructor).
        let mut cipher = aes_gcm::AesGcm::new(aes::KeySize::KeySize128, key, nonce, &[]);
        let mut ciphertext = vec![0_u8; message.len()];
        let mut mac = vec![0_u8; Self::MAC_LEN];
        cipher.encrypt(message, &mut ciphertext, &mut mac);
        CipherOutput { ciphertext, mac }
    }

    fn open(output: &mut [u8], enc: &CipherOutput, nonce: &[u8], key: &[u8]) -> Result<(), ()> {
        let mut cipher = aes_gcm::AesGcm::new(aes::KeySize::KeySize128, key, nonce, &[]);

        if cipher.decrypt(&enc.ciphertext, output, &enc.mac) {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Suite for password-based encryption provided by `rust-crypto`.
///
/// # Ciphers
///
/// - `aes-128-ctr`: AES-128 cipher in CTR mode with Keccak256-based MAC
/// - `aes-128-gcm`: AES-128 cipher in GCM mode
///
/// # KDFs
///
/// - `scrypt`: `scrypt` KDF with the original parametrization (not the libsodium one)
///
/// # Examples
///
/// This suite can be used for compatibility with Ethereum keystores.
///
/// ```
/// use rand::thread_rng;
/// use pwbox::{Eraser, ErasedPwBox, Suite, rcrypto::RustCrypto};
/// # use pwbox::{Error, rcrypto::Scrypt};
///
/// # fn main() -> Result<(), Error> {
/// // Create a new box.
/// let pwbox = RustCrypto::build_box(&mut thread_rng())
/// #   .kdf(Scrypt::custom(2, 1))
///     .seal(b"correct horse", b"battery staple")
///     .unwrap();
///
/// // Read from existing box.
/// let mut eraser = Eraser::new();
/// eraser.add_suite::<RustCrypto>();
/// let erased: ErasedPwBox = // deserialized from some format
/// #   eraser.erase(&pwbox).unwrap();
/// let plaintext = eraser.restore(&erased)?.open(b"correct horse")?;
/// # assert_eq!(&*plaintext, b"battery staple");
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum RustCrypto {}

impl Suite for RustCrypto {
    type Cipher = CipherWithMac<Aes128Ctr, Keccak256>;
    type DeriveKey = Scrypt;

    fn add_ciphers_and_kdfs(eraser: &mut Eraser) {
        // `aes-128-ctr` is the name used in Ethereum keystores. A more appropriate name
        // would be something like `aes-128-ctr/keccak256`, but the shorter one is used here
        // for compatibility.
        eraser
            .add_cipher::<Self::Cipher>("aes-128-ctr")
            .add_cipher::<Aes128Gcm>("aes-128-gcm")
            .add_kdf::<Scrypt>("scrypt");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        erased::{test_kdf_and_cipher_corruption, ErasedPwBox},
        test_kdf_and_cipher,
    };

    #[test]
    fn aes_with_keccak_mac() {
        use rand::{thread_rng, RngCore};

        const MESSAGE: &[u8] = b"battery staple";
        type Ci = CipherWithMac<Aes128Ctr, Keccak256>;

        let mut rng = thread_rng();
        let mut key = vec![0; Ci::KEY_LEN];
        rng.fill_bytes(&mut key);
        let mut nonce = vec![0; Ci::NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let mut sealed = Ci::seal(MESSAGE, &nonce, &key);
        let mut plaintext = vec![0; MESSAGE.len()];
        Ci::open(&mut plaintext, &sealed, &nonce, &key).unwrap();
        assert_eq!(&*plaintext, MESSAGE);

        // Corrupt MAC.
        sealed.mac[0] ^= 1;
        let mut plaintext = vec![0; MESSAGE.len()];
        assert!(Ci::open(&mut plaintext, &sealed, &nonce, &key).is_err());
    }

    // `rust-crypto` is quite slow in debug mode, so we use *very* easy parameters here
    // (much easier than even `Scrypt::light()`) for the sake of testing.
    fn light_scrypt() -> Scrypt {
        Scrypt::custom(6, 16)
    }

    #[test]
    fn scrypt_and_aes128ctr() {
        test_kdf_and_cipher::<_, CipherWithMac<Aes128Ctr, Keccak256>>(light_scrypt());
    }

    #[test]
    fn scrypt_and_aes128ctr_corruption() {
        test_kdf_and_cipher_corruption::<_, CipherWithMac<Aes128Ctr, Keccak256>>(light_scrypt());
    }

    #[test]
    fn scrypt_and_aes128gcm() {
        test_kdf_and_cipher::<_, Aes128Gcm>(light_scrypt());
    }

    #[test]
    fn scrypt_and_aes128gcm_corruption() {
        test_kdf_and_cipher_corruption::<_, Aes128Gcm>(light_scrypt());
    }

    #[test]
    fn ethstore_functionality() {
        use rand::thread_rng;

        const PASSWORD: &str = "correct horse battery staple";
        const MESSAGE: &[u8] = b"1234567890";

        let mut eraser = Eraser::new();
        let eraser = eraser.add_suite::<RustCrypto>();

        let mut rng = thread_rng();
        let pwbox = RustCrypto::build_box(&mut rng)
            .kdf(light_scrypt())
            .seal(PASSWORD, MESSAGE)
            .unwrap();

        let erased = eraser.erase(&pwbox).unwrap();
        let pwbox_copy = eraser.restore(&erased).unwrap();
        assert_eq!(MESSAGE, &*pwbox_copy.open(PASSWORD).unwrap());
    }

    #[test]
    fn ethstore_compatibility() {
        use serde_json;

        const PASSWORD: &str = "foo";
        const MESSAGE_HEX: &str = "fa7b3db73dc7dfdf8c5fbdb796d741e4488628c41fc4febd9160a866ba0f35";
        const PWBOX: &str = r#"{
            "cipher" : "aes-128-ctr",
            "cipherparams" : {
                "iv" : "e0c41130a323adc1446fc82f724bca2f"
            },
            "ciphertext" : "9517cd5bdbe69076f9bf5057248c6c050141e970efa36ce53692d5d59a3984",
            "kdf" : "scrypt",
            "kdfparams" : {
                "dklen" : 32,
                "n" : 2,
                "r" : 8,
                "p" : 1,
                "salt" : "711f816911c92d649fb4c84b047915679933555030b3552c1212609b38208c63"
            },
            "mac" : "d5e116151c6aa71470e67a7d42c9620c75c4d23229847dcc127794f0732b0db5"
        }"#;

        let mut eraser = Eraser::new();
        let eraser = eraser.add_suite::<RustCrypto>();

        let message = hex::decode(MESSAGE_HEX).unwrap();
        let erased: ErasedPwBox = serde_json::from_str(&PWBOX).unwrap();
        let pwbox = eraser.restore(&erased).unwrap();
        assert_eq!(message, &*pwbox.open(PASSWORD).unwrap());
    }
}
