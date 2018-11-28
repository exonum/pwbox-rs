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

//! Password-based encryption and decryption for Rust.
//!
//! # Overview
//!
//! This crate provides the container for password-based encryption, [`PwBox`],
//! which can be composed of [key derivation] and authenticated symmetric [`Cipher`] cryptographic
//! primitives. In turn, authenticated symmetric ciphers can be composed from an
//! [`UnauthenticatedCipher`] and a message authentication code ([`Mac`]).
//! The crate provides several pluggable cryptographic [`Suite`]s with these primitives:
//!
//! - [`Sodium`]
//! - [`RustCrypto`] (provides compatibility with Ethereum keystore; see its docs for more
//!   details)
//!
//! There is also [`Eraser`], which allows to (de)serialize [`PwBox`]es from any `serde`-compatible
//! format, such as JSON or TOML.
//!
//! [`PwBox`]: struct.PwBox.html
//! [key derivation]: trait.DeriveKey.html
//! [`Cipher`]: trait.Cipher.html
//! [`UnauthenticatedCipher`]: trait.UnauthenticatedCipher.html
//! [`Mac`]: trait.Mac.html
//! [`Suite`]: trait.Suite.html
//! [`Sodium`]: sodium/enum.Sodium.html
//! [`RustCrypto`]: rcrypto/enum.RustCrypto.html
//! [`Eraser`]: struct.Eraser.html
//!
//! # Naming
//!
//! `PwBox` name was produced by combining two libsodium names: `pwhash` for password-based KDFs
//! and `*box` for ciphers.
//!
//! # Examples
//!
//! Using the `Sodium` cryptosuite:
//!
//! ```
//! # extern crate rand;
//! # extern crate pwbox;
//! extern crate serde_json;
//! use rand::thread_rng;
//! use pwbox::{Eraser, ErasedPwBox, Suite, sodium::Sodium};
//! # use pwbox::{Error, sodium::Scrypt};
//!
//! # fn main() -> Result<(), Error> {
//! // Create a new box.
//! let pwbox = Sodium::build_box(&mut thread_rng())
//! #   .kdf(Scrypt::light())
//!     .seal(b"correct horse", b"battery staple")
//!     .unwrap();
//!
//! // Serialize box.
//! let mut eraser = Eraser::new();
//! eraser.add_suite::<Sodium>();
//! let erased: ErasedPwBox = eraser.erase(pwbox).unwrap();
//! println!("{}", serde_json::to_string_pretty(&erased).unwrap());
//! // Deserialize box back.
//! let plaintext = eraser.restore(&erased)?.open(b"correct horse")?;
//! assert_eq!(&*plaintext, b"battery staple");
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs, missing_debug_implementations)]

extern crate clear_on_drop;
#[macro_use]
extern crate smallvec;
extern crate failure;
extern crate failure_derive;
extern crate rand_core;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate hex_buffer_serde;
extern crate serde_json;

// Crates for testing.
#[cfg(test)]
extern crate rand;
#[cfg(test)]
#[macro_use]
extern crate assert_matches;

use clear_on_drop::ClearOnDrop;
use failure::Fail;
use hex_buffer_serde::{Hex as _Hex, HexForm};
use rand_core::{CryptoRng, RngCore};
use serde_json::Error as JsonError;
use smallvec::SmallVec;

use std::{fmt, marker::PhantomData, ops::Deref};

mod cipher_with_mac;
mod erased;
mod utils;

// Crypto backends.
#[cfg(feature = "rust-crypto")]
pub mod rcrypto;
#[cfg(feature = "exonum_sodiumoxide")]
pub mod sodium;

pub use cipher_with_mac::{CipherWithMac, Mac, UnauthenticatedCipher};
pub use erased::{ErasedPwBox, Eraser, Suite};

/// Expected upper bound on byte buffers created during encryption / decryption.
const BUFFER_SIZE: usize = 256;

/// Container for data obtained after opening a `PwBox`.
///
/// # Safety
///
/// The container is zeroed on drop. Internally, it uses [`SmallVec`]; hence,
/// the data with size <= 256 bytes is stored on stack, which further
/// reduces possibility of data leakage.
///
/// [`SmallVec`]: https://docs.rs/smallvec/0.6.6/smallvec/struct.SmallVec.html
#[derive(Clone)]
pub struct SensitiveData(SmallVec<[u8; BUFFER_SIZE]>);

impl SensitiveData {
    fn zeros(len: usize) -> Self {
        SensitiveData(smallvec![0; len])
    }
}

impl fmt::Debug for SensitiveData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SensitiveData").field(&"_").finish()
    }
}

impl Deref for SensitiveData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Drop for SensitiveData {
    fn drop(&mut self) {
        let handle = ClearOnDrop::new(&mut self.0);
        drop(handle); // this is where the bytes are cleared
    }
}

/// Key derivation function.
pub trait DeriveKey: 'static {
    /// Returns byte size of salt supplied to the KDF.
    fn salt_len(&self) -> usize;

    /// Derives a key from the given password and salt.
    ///
    /// # Safety
    ///
    /// When used within `PwBox`, `salt` is guaranteed to have the correct size.
    fn derive_key(&self, buf: &mut [u8], password: &[u8], salt: &[u8])
        -> Result<(), Box<dyn Fail>>;
}

impl DeriveKey for Box<dyn DeriveKey> {
    fn salt_len(&self) -> usize {
        (**self).salt_len()
    }

    fn derive_key(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
    ) -> Result<(), Box<dyn Fail>> {
        (**self).derive_key(buf, password, salt)
    }
}

/// Authenticated symmetric cipher.
pub trait Cipher: 'static {
    /// Byte size of a key.
    fn key_len(&self) -> usize;
    /// Byte size of a nonce (aka initialization vector, or IV).
    fn nonce_len(&self) -> usize;
    /// Byte size of a message authentication code (MAC).
    fn mac_len(&self) -> usize;

    /// Encrypts `message` with the provided `key` and `nonce`.
    ///
    /// # Safety
    ///
    /// When used within [`PwBox`], `key` and `nonce` are guaranteed to have correct sizes.
    ///
    /// [`PwBox`]: struct.PwBox.html
    fn seal(&self, message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput;

    /// Decrypts `encrypted` message with the provided `key` and `nonce` and stores
    /// the result into `output`. If the MAC does not verify, returns an error.
    ///
    /// # Safety
    ///
    /// When used within [`PwBox`], `key`, `nonce`, `encrypted.mac` and `output` are guaranteed to
    /// have correct sizes.
    ///
    /// [`PwBox`]: struct.PwBox.html
    fn open(
        &self,
        output: &mut [u8],
        encrypted: &CipherOutput,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<(), ()>;
}

/// Output of a `Cipher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOutput {
    /// Encrypted data. Has the same size as the original data.
    #[serde(with = "HexForm")]
    pub ciphertext: Vec<u8>,

    /// Message authentication code for the `ciphertext`.
    #[serde(with = "HexForm")]
    pub mac: Vec<u8>,
}

impl Cipher for Box<dyn Cipher> {
    fn key_len(&self) -> usize {
        (**self).key_len()
    }

    fn nonce_len(&self) -> usize {
        (**self).nonce_len()
    }

    fn mac_len(&self) -> usize {
        (**self).mac_len()
    }

    fn seal(&self, message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        (**self).seal(message, nonce, key)
    }

    fn open(
        &self,
        output: &mut [u8],
        encrypted: &CipherOutput,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<(), ()> {
        (**self).open(output, encrypted, nonce, key)
    }
}

/// Errors occurring during `PwBox` operations.
#[derive(Debug, Fail)]
pub enum Error {
    /// A cipher with the specified name is not registered.
    ///
    /// # Troubleshooting
    ///
    /// Register the cipher with the help of [`Eraser::add_cipher()`]
    /// or [`Eraser::add_suite()`] methods.
    ///
    /// [`Eraser::add_cipher()`]: struct.Eraser.html#method.add_cipher
    /// [`Eraser::add_suite()`]: struct.Eraser.html#method.add_suite
    #[fail(display = "unknown cipher: {}", _0)]
    NoCipher(String),

    /// A key derivation function with the specified name is not registered.
    ///
    /// # Troubleshooting
    ///
    /// Register the cipher with the help of [`Eraser::add_kdf()`]
    /// or [`Eraser::add_suite()`] methods.
    ///
    /// [`Eraser::add_kdf()`]: struct.Eraser.html#method.add_kdf
    /// [`Eraser::add_suite()`]: struct.Eraser.html#method.add_suite
    #[fail(display = "unknown KDF: {}", _0)]
    NoKdf(String),

    /// Failed to parse KDF parameters.
    #[fail(display = "failed to parse KDF parameters: {}", _0)]
    KdfParams(#[fail(cause)] JsonError),

    /// Incorrect nonce length encountered.
    ///
    /// This error usually means that the box is corrupted.
    #[fail(display = "incorrect nonce length")]
    NonceLen,

    /// Incorrect MAC length encountered.
    ///
    /// This error usually means that the box is corrupted.
    #[fail(display = "incorrect MAC length")]
    MacLen,

    /// Incorrect salt length encountered.
    ///
    /// This error usually means that the box is corrupted.
    #[fail(display = "incorrect salt length")]
    SaltLen,

    /// Failed to verify MAC code.
    ///
    /// This error means that either the supplied password is incorrect,
    /// or the box is corrupted.
    #[fail(display = "incorrect password or corrupted box")]
    MacMismatch,

    /// Error during KDF invocation.
    ///
    /// This error can arise if the KDF was supplied with invalid parameters,
    /// which may lead or have led to a KDF-specific error (e.g., out-of-memory).
    #[fail(display = "error during key derivation: {}", _0)]
    DeriveKey(#[fail(cause)] Box<dyn Fail>),
}

/// Password-encrypted data.
///
/// # See also
///
/// See the crate docs for an example of usage. See [`ErasedPwBox`] for serialization details.
///
/// [`ErasedPwBox`]: struct.ErasedPwBox.html
#[derive(Debug)]
pub struct PwBox<K, C> {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted: CipherOutput,
    kdf: K,
    cipher: C,
}

/// Password-encrypted box restored by `Eraser`.
pub type RestoredPwBox = PwBox<Box<dyn DeriveKey>, Box<dyn Cipher>>;

impl<K: DeriveKey + Default, C: Cipher + Default> PwBox<K, C> {
    /// Creates a new box by using default settings of the supplied KDF.
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: impl AsRef<[u8]>,
        message: impl AsRef<[u8]>,
    ) -> Result<Self, Box<dyn Fail>> {
        let (kdf, cipher) = (K::default(), C::default());
        Self::seal(kdf, cipher, rng, password, message)
    }
}

// `is_empty()` method wouldn't make much sense; in *all* valid use cases, `len() > 0`.
#[cfg_attr(feature = "cargo-clippy", allow(len_without_is_empty))]
impl<K: DeriveKey, C: Cipher> PwBox<K, C> {
    fn seal<R: RngCore + ?Sized>(
        kdf: K,
        cipher: C,
        rng: &mut R,
        password: impl AsRef<[u8]>,
        message: impl AsRef<[u8]>,
    ) -> Result<Self, Box<dyn Fail>> {
        // Create salt and nonce from RNG.
        let mut salt = SensitiveData::zeros(kdf.salt_len());
        rng.fill_bytes(&mut *salt.0);
        let mut nonce = SensitiveData::zeros(cipher.nonce_len());
        rng.fill_bytes(&mut *nonce.0);

        // Derive key from password and salt.
        let mut key = SensitiveData::zeros(cipher.key_len());
        kdf.derive_key(&mut *key.0, password.as_ref(), &*salt)?;

        let encrypted = cipher.seal(message.as_ref(), &*nonce, &*key);
        Ok(PwBox {
            salt: salt[..].to_vec(),
            nonce: nonce[..].to_vec(),
            encrypted,
            kdf,
            cipher,
        })
    }

    /// Returns the byte size of the encrypted data stored in this box.
    pub fn len(&self) -> usize {
        self.encrypted.ciphertext.len()
    }

    /// Decrypts the box into the specified container.
    ///
    /// This method should be preferred to `open()` if the `output` type implements
    /// zeroing on drop (e.g., cryptographic secrets from `sodiumoxide`).
    pub fn open_into(
        &self,
        mut output: impl AsMut<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        assert_eq!(
            output.as_mut().len(),
            self.len(),
            "please check `PwBox::len()` and provide output of fitting size"
        );

        let key_len = self.cipher.key_len();

        // Derive key from password and salt.
        let mut key = SensitiveData::zeros(key_len);
        self.kdf
            .derive_key(&mut *key.0, password.as_ref(), &self.salt)
            .map_err(Error::DeriveKey)?;

        self.cipher
            .open(output.as_mut(), &self.encrypted, &self.nonce, &*key)
            .map_err(|()| Error::MacMismatch)
    }

    /// Decrypts the box and returns its contents. The returned container is zeroed on drop
    /// and derefs to a byte slice.
    pub fn open(&self, password: impl AsRef<[u8]>) -> Result<SensitiveData, Error> {
        let mut output = SensitiveData::zeros(self.len());
        self.open_into(&mut *output.0, password).map(|()| output)
    }
}

/// Builder for `PwBox`es.
pub struct PwBoxBuilder<'a, K, C> {
    kdf: Option<K>,
    rng: &'a mut dyn RngCore,
    _cipher: PhantomData<C>,
}

impl<'a, K, C> fmt::Debug for PwBoxBuilder<'a, K, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PwBoxBuilder")
            .field("custom_kdf", &self.kdf.is_some())
            .finish()
    }
}

impl<'a, K, C> PwBoxBuilder<'a, K, C>
where
    K: DeriveKey + Clone + Default,
    C: Cipher + Default,
{
    /// Initializes the builder with a random number generator.
    pub fn new<R: RngCore + CryptoRng>(rng: &'a mut R) -> Self {
        PwBoxBuilder {
            kdf: None,
            rng,
            _cipher: PhantomData,
        }
    }

    /// Sets up a custom KDF.
    pub fn kdf(&mut self, kdf: K) -> &mut Self {
        self.kdf = Some(kdf);
        self
    }

    /// Creates a new `PwBox` with the specified password and contents.
    pub fn seal(
        &mut self,
        password: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
    ) -> Result<PwBox<K, C>, Box<dyn Fail>> {
        let cipher = C::default();
        let kdf = self.kdf.clone().unwrap_or_default();
        PwBox::seal(kdf, cipher, self.rng, password, data)
    }
}

// This function is used in testing cryptographic backends, so it's intentionally kept public.
#[cfg(test)]
#[doc(hidden)]
pub fn test_kdf_and_cipher<K, C>(kdf: K)
where
    K: DeriveKey + Clone + Default,
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
    assert_eq!(message, &*pwbox.open(PASSWORD).unwrap());
}
