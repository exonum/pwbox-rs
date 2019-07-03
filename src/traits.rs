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

//! Traits for core crypto primitives used in `PwBox`.

use failure::Fail;
use hex_buffer_serde::{Hex as _, HexForm};
use serde_derive::*;

use std::marker::PhantomData;

/// Key derivation function (KDF).
///
/// An instance of `DeriveKey` implementation corresponds to a particular set of difficulty params
/// of a particular KDF.
///
/// # Implementation notes
///
/// If you want to use a `DeriveKey` implementation with an [`Eraser`], it should
/// additionally implement the following traits:
///
/// - `Default` (should return a KDF instance with reasonable difficulty params)
/// - `Clone`
/// - `Serialize` / `Deserialize` from `serde`
///
/// [`Eraser`]: struct.Eraser.html
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
    const KEY_LEN: usize;
    /// Byte size of a nonce (aka initialization vector, or IV).
    const NONCE_LEN: usize;
    /// Byte size of a message authentication code (MAC).
    const MAC_LEN: usize;

    /// Encrypts `message` with the provided `key` and `nonce`.
    ///
    /// # Safety
    ///
    /// When used within [`PwBox`], `key` and `nonce` are guaranteed to have correct sizes.
    ///
    /// [`PwBox`]: struct.PwBox.html
    fn seal(message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput;

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
        output: &mut [u8],
        encrypted: &CipherOutput,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<(), ()>;
}

/// Helper for converting `Cipher`s into `ObjectSafeCipher`s.
#[derive(Debug)]
pub(crate) struct CipherObject<T>(PhantomData<T>);

impl<T> Default for CipherObject<T> {
    fn default() -> Self {
        CipherObject(PhantomData)
    }
}

/// Object-safe equivalent of a `Cipher`.
pub(crate) trait ObjectSafeCipher: 'static {
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;
    fn mac_len(&self) -> usize;

    fn seal(&self, message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput;
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

impl<T: Cipher> ObjectSafeCipher for CipherObject<T> {
    fn key_len(&self) -> usize {
        T::KEY_LEN
    }

    fn nonce_len(&self) -> usize {
        T::NONCE_LEN
    }

    fn mac_len(&self) -> usize {
        T::MAC_LEN
    }

    fn seal(&self, message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        T::seal(message, nonce, key)
    }

    fn open(
        &self,
        output: &mut [u8],
        encrypted: &CipherOutput,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<(), ()> {
        T::open(output, encrypted, nonce, key)
    }
}

impl ObjectSafeCipher for Box<dyn ObjectSafeCipher> {
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
