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
//! - [`PureCrypto`] (pure Rust implementation; good for comiling into WASM
//!   or for other constrained environments).
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
//! [`PureCrypto`]: pure/enum.PureCrypto.html
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
//! # use failure::Error;
//! use rand::thread_rng;
//! use pwbox::{Eraser, ErasedPwBox, Suite, sodium::Sodium};
//! # use pwbox::sodium::Scrypt;
//!
//! # fn main() -> Result<(), Error> {
//! // Create a new box.
//! let pwbox = Sodium::build_box(&mut thread_rng())
//! #   .kdf(Scrypt::light())
//!     .seal(b"correct horse", b"battery staple")?;
//!
//! // Serialize box.
//! let mut eraser = Eraser::new();
//! eraser.add_suite::<Sodium>();
//! let erased: ErasedPwBox = eraser.erase(&pwbox)?;
//! println!("{}", serde_json::to_string_pretty(&erased)?);
//! // Deserialize box back.
//! let plaintext = eraser.restore(&erased)?.open(b"correct horse")?;
//! assert_eq!(&*plaintext, b"battery staple");
//! # Ok(())
//! # }
//! ```

#![no_std]
#![deny(missing_docs, missing_debug_implementations)]

extern crate alloc;

use failure::Fail;
use rand_core::{CryptoRng, RngCore};
use serde_json::Error as JsonError;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, marker::PhantomData};

mod cipher_with_mac;
mod erased;
mod traits;
mod utils;

// Crypto backends.
#[cfg(feature = "pure")]
pub mod pure;
#[cfg(feature = "rust-crypto")]
pub mod rcrypto;
#[cfg(feature = "exonum_sodiumoxide")]
pub mod sodium;

pub use cipher_with_mac::{CipherWithMac, Mac, UnauthenticatedCipher};
pub use erased::{EraseError, ErasedPwBox, Eraser, Suite};
pub use traits::{Cipher, CipherOutput, DeriveKey};
pub use utils::{ScryptParams, SensitiveData};

use traits::{CipherObject, ObjectSafeCipher};

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

/// The core cryptographic object of the library: a box containing randomly generated `salt`
/// and cipher `nonce`, as well as the ciphertext and the KDF / cipher info.
///
/// Reused within `PwBox` and `RestoredPwBox`.
#[derive(Debug)]
struct PwBoxInner<K, C> {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted: CipherOutput,
    kdf: K,
    cipher: C,
}

impl<K: DeriveKey, C: ObjectSafeCipher> PwBoxInner<K, C> {
    fn seal<R: RngCore + ?Sized>(
        kdf: K,
        cipher: C,
        rng: &mut R,
        password: impl AsRef<[u8]>,
        message: impl AsRef<[u8]>,
    ) -> Result<Self, Box<dyn Fail>> {
        // Create salt and nonce from RNG.
        let mut salt = SensitiveData::zeros(kdf.salt_len());
        rng.fill_bytes(salt.bytes_mut());
        let mut nonce = SensitiveData::zeros(cipher.nonce_len());
        rng.fill_bytes(nonce.bytes_mut());

        // Derive key from password and salt.
        let mut key = SensitiveData::zeros(cipher.key_len());
        kdf.derive_key(key.bytes_mut(), password.as_ref(), &*salt)?;

        let encrypted = cipher.seal(message.as_ref(), &*nonce, &*key);
        Ok(PwBoxInner {
            salt: salt[..].to_vec(),
            nonce: nonce[..].to_vec(),
            encrypted,
            kdf,
            cipher,
        })
    }

    fn len(&self) -> usize {
        self.encrypted.ciphertext.len()
    }

    fn open_into(
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
            .derive_key(key.bytes_mut(), password.as_ref(), &self.salt)
            .map_err(Error::DeriveKey)?;

        self.cipher
            .open(output.as_mut(), &self.encrypted, &self.nonce, &*key)
            .map_err(|()| Error::MacMismatch)
    }

    fn open(&self, password: impl AsRef<[u8]>) -> Result<SensitiveData, Error> {
        let mut output = SensitiveData::zeros(self.len());
        self.open_into(output.bytes_mut(), password)
            .map(|()| output)
    }
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
    inner: PwBoxInner<K, CipherObject<C>>,
}

impl<K: DeriveKey + Default, C: Cipher> PwBox<K, C> {
    /// Creates a new box by using default settings of the supplied KDF.
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        password: impl AsRef<[u8]>,
        message: impl AsRef<[u8]>,
    ) -> Result<Self, Box<dyn Fail>> {
        let (kdf, cipher) = (K::default(), CipherObject::default());
        PwBoxInner::seal(kdf, cipher, rng, password, message).map(|inner| PwBox { inner })
    }
}

// `is_empty()` method wouldn't make much sense; in *all* valid use cases, `len() > 0`.
#[allow(clippy::len_without_is_empty)]
impl<K: DeriveKey, C: Cipher> PwBox<K, C> {
    /// Returns the byte size of the encrypted data stored in this box.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Decrypts the box into the specified container.
    ///
    /// This method should be preferred to `open()` if the `output` type implements
    /// zeroing on drop (e.g., cryptographic secrets from `sodiumoxide`).
    pub fn open_into(
        &self,
        output: impl AsMut<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        self.inner.open_into(output, password)
    }

    /// Decrypts the box and returns its contents. The returned container is zeroed on drop
    /// and derefs to a byte slice.
    pub fn open(&self, password: impl AsRef<[u8]>) -> Result<SensitiveData, Error> {
        self.inner.open(password)
    }
}

/// Password-encrypted box restored after deserialization.
///
/// If the box may be corrupted, it may make sense to check its length
/// with the [`len()`] method before `open`ing the box.
///
/// [`len()`]: #method.len
pub struct RestoredPwBox {
    inner: PwBoxInner<Box<dyn DeriveKey>, Box<dyn ObjectSafeCipher>>,
}

impl fmt::Debug for RestoredPwBox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RestoredPwBox").finish()
    }
}

// `is_empty()` method wouldn't make much sense; in *all* valid use cases, `len() > 0`.
#[allow(clippy::len_without_is_empty)]
impl RestoredPwBox {
    /// Returns the byte size of the encrypted data stored in this box.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Decrypts the box into the specified container.
    ///
    /// This method should be preferred to `open()` if the `output` type implements
    /// zeroing on drop (e.g., cryptographic secrets from `sodiumoxide`).
    pub fn open_into(
        &self,
        output: impl AsMut<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        self.inner.open_into(output, password)
    }

    /// Decrypts the box and returns its contents. The returned container is zeroed on drop
    /// and derefs to a byte slice.
    pub fn open(&self, password: impl AsRef<[u8]>) -> Result<SensitiveData, Error> {
        self.inner.open(password)
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
    C: Cipher,
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
        let cipher: CipherObject<C> = Default::default();
        let kdf = self.kdf.clone().unwrap_or_default();
        PwBoxInner::seal(kdf, cipher, self.rng, password, data).map(|inner| PwBox { inner })
    }
}

// This function is used in testing cryptographic backends, so it's intentionally kept public.
#[cfg(test)]
#[doc(hidden)]
pub fn test_kdf_and_cipher<K, C>(kdf: K)
where
    K: DeriveKey + Clone + Default,
    C: Cipher,
{
    use alloc::vec;
    use rand::thread_rng;

    const PASSWORD: &str = "correct horse battery staple";

    let mut rng = thread_rng();
    let mut message = vec![0_u8; 64];
    rng.fill_bytes(&mut message);

    let pwbox = PwBoxBuilder::<_, C>::new(&mut rng)
        .kdf(kdf)
        .seal(PASSWORD, &message)
        .unwrap();
    assert_eq!(message.len(), pwbox.len());
    assert_eq!(message, &*pwbox.open(PASSWORD).unwrap());

    let mut buffer = [0_u8; 64];
    // As [u8; 64] does not implement AsMut<[u8]> (the array length is larger than
    // the stopgap threshold 32), we need to index it explicitly.
    pwbox.open_into(&mut buffer[..], PASSWORD).unwrap();
    assert_eq!(buffer[..], *message);
}
