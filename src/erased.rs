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

use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{self, Error as JsonError, Value as JsonValue};

use std::{any::TypeId, collections::HashMap, fmt};

use utils::HexBytes;
use {Cipher, CipherOutput, DeriveKey, Error, PwBox, PwBoxBuilder, RestoredPwBox};

/// Password-encrypted box suitable for (de)serialization.
///
/// # Serialization
///
/// When used with a human-readable format (JSON, YAML, TOML, ...), the `pwbox`
/// is serialized as the following structure:
///
/// ```
/// extern crate toml;
/// # extern crate pwbox;
/// # use pwbox::{Eraser, sodium::Sodium};
///
/// const TOML: &str = r#"
/// ciphertext = 'cd9d2fb2355d8c60d92dcc860abc0c4b20ddd12dd52a4dd53caca0a2f87f7f5f'
/// mac = '83ae22646d7834f254caea78862eafda'
/// kdf = 'scrypt-nacl'
/// cipher = 'xsalsa20-poly1305'
///
/// [kdfparams]
/// salt = '87d68fb57d9c2331cf2bd9fdd7551057798bd36d0d2999481311cfae39863691'
/// memlimit = 16777216
/// opslimit = 524288
///
/// [cipherparams]
/// iv = 'db39c466e2f8ae7fbbc857df48d99254017b059624af7106'
/// "#;
///
/// let pwbox = toml::from_str(TOML).unwrap();
/// let pwbox = Eraser::new().add_suite::<Sodium>().restore(&pwbox).unwrap();
/// assert!(pwbox.open("correct horse battery staple").is_ok());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasedPwBox {
    #[serde(flatten)]
    encrypted: CipherOutput,
    kdf: String,
    cipher: String,
    #[serde(rename = "kdfparams")]
    kdf_params: KdfParams,
    #[serde(rename = "cipherparams")]
    cipher_params: CipherParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    #[serde(with = "HexBytes")]
    salt: Vec<u8>,
    #[serde(flatten)]
    inner: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CipherParams {
    #[serde(with = "HexBytes")]
    iv: Vec<u8>,
}

type CipherFactory = Box<dyn Fn() -> Box<dyn Cipher>>;
type KdfFactory = Box<dyn Fn(JsonValue) -> Result<Box<dyn DeriveKey>, JsonError>>;

/// Helper structure to convert password-encrypted boxes to a serializable format and back.
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "exonum_libsodium", feature = "rust-crypto"))]
/// # fn main() {
/// # extern crate pwbox;
/// # extern crate rand;
/// # use rand::thread_rng;
/// # use pwbox::{Eraser, Suite,
/// #     rcrypto::{Scrypt as SomeKdf, Aes128Gcm as SomeCipher},
/// #     sodium::Sodium as SomeSuite};
/// let mut eraser = Eraser::new();
/// // Register separate KDFs and ciphers
/// eraser.add_kdf::<SomeKdf>("some-kdf");
/// eraser.add_cipher::<SomeCipher>("some-cipher");
/// // Add a suite.
/// eraser.add_suite::<SomeSuite>();
///
/// // Erase a `PwBox`.
/// let pwbox = SomeSuite::build_box(&mut thread_rng())
///     .seal("password", b"some data")
///     .unwrap();
/// let erased = eraser.erase(pwbox).unwrap();
/// // `erased` can now be serialized somewhere, e.g., in JSON format.
///
/// // Restore a `PwBox`.
/// let restored = eraser.restore(&erased).unwrap();
/// assert_eq!(restored.open("password").unwrap(), b"some data");
/// # } // main
/// # #[cfg(not(all(feature = "exonum_libsodium", feature = "rust-crypto")))]
/// # fn main() {}
/// ```
pub struct Eraser {
    ciphers: HashMap<String, CipherFactory>,
    kdfs: HashMap<String, KdfFactory>,
    cipher_names: HashMap<TypeId, String>,
    kdf_names: HashMap<TypeId, String>,
}

impl fmt::Debug for Eraser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Eraser")
            .field("ciphers", &self.ciphers.keys().collect::<Vec<_>>())
            .field("kdfs", &self.kdfs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for Eraser {
    fn default() -> Self {
        Eraser::new()
    }
}

impl Eraser {
    /// Creates an `Eraser` with no ciphers or KDFs.
    pub fn new() -> Self {
        Eraser {
            ciphers: HashMap::new(),
            kdfs: HashMap::new(),
            cipher_names: HashMap::new(),
            kdf_names: HashMap::new(),
        }
    }

    /// Adds a cipher.
    ///
    /// # Panics
    ///
    /// Panics if the cipher is already registered under a different name, or if `cipher_name`
    /// is already registered.
    pub fn add_cipher<C>(&mut self, cipher_name: &str) -> &mut Self
    where
        C: Cipher + Default,
    {
        let factory = || Box::new(C::default()) as Box<dyn Cipher>;
        let old_cipher = self
            .ciphers
            .insert(cipher_name.to_owned(), Box::new(factory));
        assert!(
            old_cipher.is_none(),
            "cipher name already registered: {}",
            cipher_name
        );
        let old_name = self
            .cipher_names
            .insert(TypeId::of::<C>(), cipher_name.to_owned());
        assert!(
            old_name.is_none(),
            "cipher {} already registered under name {}",
            cipher_name,
            old_name.unwrap()
        );
        self
    }

    /// Adds a key derivation function.
    ///
    /// # Panics
    ///
    /// Panics if the KDF is already registered under a different name, or if `kdf_name`
    /// is already registered.
    pub fn add_kdf<K>(&mut self, kdf_name: &str) -> &mut Self
    where
        K: DeriveKey + DeserializeOwned + Default,
    {
        let factory = |options| {
            let kdf: K = serde_json::from_value(options)?;
            Ok(Box::new(kdf) as Box<dyn DeriveKey>)
        };

        let old_kdf = self.kdfs.insert(kdf_name.to_owned(), Box::new(factory));
        assert!(
            old_kdf.is_none(),
            "cipher name already registered: {}",
            kdf_name
        );
        let old_name = self
            .kdf_names
            .insert(TypeId::of::<K>(), kdf_name.to_owned());
        assert!(
            old_name.is_none(),
            "KDF {} already registered under name {}",
            kdf_name,
            old_name.unwrap()
        );
        self
    }

    /// Adds all KDFs and ciphers from the specified `Suite`.
    ///
    /// # Panics
    ///
    /// This method panics if any KDF or cipher in the suite (or its name)
    /// have been registered previously. A panic is also raised if the suite
    /// has not registered its recommended cipher or KDF.
    pub fn add_suite<S: Suite>(&mut self) -> &mut Self {
        S::add_ciphers_and_kdfs(self);
        assert!(
            self.lookup_kdf::<S::DeriveKey>().is_some(),
            "recommended KDF from suite not added"
        );
        assert!(
            self.lookup_cipher::<S::Cipher>().is_some(),
            "recommended cipher from suite not added"
        );
        self
    }

    fn lookup_cipher<C>(&self) -> Option<&String>
    where
        C: Cipher,
    {
        self.cipher_names.get(&TypeId::of::<C>())
    }

    fn lookup_kdf<K>(&self) -> Option<&String>
    where
        K: DeriveKey,
    {
        self.kdf_names.get(&TypeId::of::<K>())
    }

    /// Converts a `pwbox` into serializable form.
    pub fn erase<K, C>(&self, pwbox: PwBox<K, C>) -> Result<ErasedPwBox, PwBox<K, C>>
    where
        K: DeriveKey + Serialize,
        C: Cipher,
    {
        let kdf = match self.lookup_kdf::<K>() {
            Some(kdf) => kdf,
            None => return Err(pwbox),
        };
        let cipher = match self.lookup_cipher::<C>() {
            Some(cipher) => cipher,
            None => return Err(pwbox),
        };
        let kdf_params = match serde_json::to_value(&pwbox.kdf) {
            Ok(params) => params,
            Err(_) => return Err(pwbox),
        };

        Ok(ErasedPwBox {
            encrypted: pwbox.encrypted,
            kdf: kdf.to_owned(),
            kdf_params: KdfParams {
                salt: pwbox.salt,
                inner: kdf_params,
            },
            cipher: cipher.to_owned(),
            cipher_params: CipherParams { iv: pwbox.nonce },
        })
    }

    /// Restores a `PwBox` from the serialized form.
    pub fn restore(&self, erased: &ErasedPwBox) -> Result<RestoredPwBox, Error> {
        let kdf_factory = self
            .kdfs
            .get(&erased.kdf)
            .ok_or_else(|| Error::NoKdf(erased.kdf.clone()))?;
        let cipher = self
            .ciphers
            .get(&erased.cipher)
            .ok_or_else(|| Error::NoCipher(erased.cipher.clone()))?();
        let kdf = kdf_factory(erased.kdf_params.inner.clone()).map_err(Error::KdfParams)?;

        // Check buffer lengths.
        if erased.kdf_params.salt.len() != kdf.salt_len() {
            return Err(Error::SaltLen);
        }
        if erased.cipher_params.iv.len() != cipher.nonce_len() {
            return Err(Error::NonceLen);
        }
        if erased.encrypted.mac.len() != cipher.mac_len() {
            return Err(Error::MacLen);
        }

        Ok(PwBox {
            salt: erased.kdf_params.salt.clone(),
            nonce: erased.cipher_params.iv.clone(),
            encrypted: erased.encrypted.clone(),
            kdf,
            cipher,
        })
    }
}

/// Cryptographic suite providing ciphers and KDFs for password-based encryption.
pub trait Suite {
    /// Recommended cipher for this suite.
    type Cipher: Cipher + Clone + Default;
    /// Recommended KDF for this suite.
    type DeriveKey: DeriveKey + Clone + Default;

    /// Initializes a `PwBoxBuilder` with the recommended cipher and KDF.
    fn build_box<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> PwBoxBuilder<Self::DeriveKey, Self::Cipher> {
        PwBoxBuilder::new(rng)
    }

    /// Adds ciphers and KDFs from this suite into the specified `Eraser`.
    fn add_ciphers_and_kdfs(eraser: &mut Eraser);
}

// This function is used in testing cryptographic backends, so it's public intentionally.
#[cfg(test)]
#[doc(hidden)]
pub fn test_kdf_and_cipher_corruption<K, C>(kdf: K)
where
    K: DeriveKey + Clone + Default + Serialize + DeserializeOwned,
    C: Cipher + Default,
{
    use rand::thread_rng;

    const PASSWORD: &str = "correct horse battery staple";

    let mut rng = thread_rng();
    let mut message = vec![0_u8; 64];
    rng.fill_bytes(&mut message);

    let pwbox = PwBoxBuilder::<_, C>::new(&mut rng)
        .kdf(kdf)
        .seal(PASSWORD, &message)
        .unwrap();

    // All corrupted input needs to pass through `Eraser` / `ErasedPwBox`, so we test them.
    let mut eraser = Eraser::new();
    let eraser = eraser.add_cipher::<C>("cipher").add_kdf::<K>("kdf");
    let mut erased = eraser.erase(pwbox).map_err(drop).unwrap();

    // Lengthen MAC.
    erased.encrypted.mac.push(b'!');
    assert_matches!(
        eraser.restore(&erased).map(drop).unwrap_err(),
        Error::MacLen
    );
    // Shorten MAC.
    erased.encrypted.mac.pop();
    if let Some(last_byte) = erased.encrypted.mac.pop() {
        assert_matches!(
            eraser.restore(&erased).map(drop).unwrap_err(),
            Error::MacLen
        );
        erased.encrypted.mac.push(last_byte);
    }

    // Lengthen salt.
    erased.kdf_params.salt.push(b'!');
    assert_matches!(
        eraser.restore(&erased).map(drop).unwrap_err(),
        Error::SaltLen
    );
    // Shorten salt.
    erased.kdf_params.salt.pop();
    if let Some(last_byte) = erased.kdf_params.salt.pop() {
        assert_matches!(
            eraser.restore(&erased).map(drop).unwrap_err(),
            Error::SaltLen
        );
        erased.kdf_params.salt.push(last_byte);
    }

    // Lengthen nonce.
    erased.cipher_params.iv.push(b'!');
    assert_matches!(
        eraser.restore(&erased).map(drop).unwrap_err(),
        Error::NonceLen
    );
    // Shorten nonce.
    erased.cipher_params.iv.pop();
    if let Some(last_byte) = erased.cipher_params.iv.pop() {
        assert_matches!(
            eraser.restore(&erased).map(drop).unwrap_err(),
            Error::NonceLen
        );
        erased.cipher_params.iv.push(last_byte);
    }

    // Mutate MAC.
    erased.encrypted.mac[0] ^= 1;
    let restored = eraser.restore(&erased).unwrap();
    assert_matches!(restored.open(PASSWORD).unwrap_err(), Error::MacMismatch);
    erased.encrypted.mac[0] ^= 1;

    // Mutate ciphertext.
    erased.encrypted.ciphertext[1] ^= 128;
    let restored = eraser.restore(&erased).unwrap();
    assert_matches!(restored.open(PASSWORD).unwrap_err(), Error::MacMismatch);
    erased.encrypted.ciphertext[1] ^= 128;

    // Mutate password.
    let mut password = PASSWORD.as_bytes().to_vec();
    password[2] ^= 16;
    assert_matches!(restored.open(&password).unwrap_err(), Error::MacMismatch);
}

#[cfg(feature = "exonum_sodiumoxide")]
#[test]
fn erase_pwbox() {
    use rand::thread_rng;
    use sodium::{Scrypt, XSalsa20Poly1305};

    const PASSWORD: &str = "correct horse battery staple";
    const MESSAGE: &[u8] = b"1234567890";

    let mut eraser = Eraser::new();
    let eraser = eraser
        .add_kdf::<Scrypt>("scrypt-nacl")
        .add_cipher::<XSalsa20Poly1305>("xsalsa20-poly1305");

    let pwbox =
        PwBox::<Scrypt, XSalsa20Poly1305>::new(&mut thread_rng(), PASSWORD, MESSAGE).unwrap();

    let erased = eraser.erase(pwbox).unwrap();
    let pwbox_copy = eraser.restore(&erased).unwrap();
    assert_eq!(pwbox_copy.open(PASSWORD).unwrap(), MESSAGE.to_vec());
}
