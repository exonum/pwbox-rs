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

//! Utilities for constructing `Cipher` from an unauthenticated symmetric cipher and a MAC.

use constant_time_eq::constant_time_eq;

use core::marker::PhantomData;

use crate::{alloc::Vec, Cipher, CipherOutput};

/// Symmetric cipher without built-in authentication.
pub trait UnauthenticatedCipher: 'static {
    /// Byte size of a key for this cipher.
    const KEY_LEN: usize;
    /// Byte size of a nonce (aka initialization vector, IV) for this cipher.
    const NONCE_LEN: usize;

    /// Encrypts or decrypts `message` in place, given the `nonce` and `key`.
    ///
    /// # Safety
    ///
    /// When used within [`PwBox`](crate::PwBox), `nonce` and `key` are guaranteed
    /// to have correct sizes.
    fn seal_or_open(message: &mut [u8], nonce: &[u8], key: &[u8]);
}

/// Message authentication code.
pub trait Mac: 'static {
    /// Byte size of a MAC key.
    const KEY_LEN: usize;
    /// Byte size of the MAC output.
    const MAC_LEN: usize;

    /// Digests a message under the specified key.
    ///
    /// The output of this method **must** have size `MAC_LEN`.
    ///
    /// # Safety
    ///
    /// When used within [`PwBox`](crate::PwBox), `key` is guaranteed to have the correct size.
    fn digest(key: &[u8], message: &[u8]) -> Vec<u8>;
}

/// Authenticated cipher constructed from an ordinary symmetric cipher and a MAC construction.
///
/// See [`Cipher` implementation] for details how this implementation works.
///
/// [`Cipher` implementation]: #impl-Cipher
#[derive(Debug)]
pub struct CipherWithMac<C, M> {
    _cipher: PhantomData<C>,
    _mac: PhantomData<M>,
}

impl<C, M> Cipher for CipherWithMac<C, M>
where
    C: UnauthenticatedCipher,
    M: Mac,
{
    /// Equals to the sum of key sizes for the cipher and MAC.
    const KEY_LEN: usize = C::KEY_LEN + M::KEY_LEN;

    const NONCE_LEN: usize = C::NONCE_LEN;
    const MAC_LEN: usize = M::MAC_LEN;

    /// Works as follows:
    ///
    /// 1. Split the key into `cipher_key` (first bytes of the key) and `mac_key`
    ///   (remaining bytes).
    /// 2. Encrypt the `message` using the cipher under `cipher_key` and `nonce`.
    /// 3. Compute MAC over the ciphertext with `mac_key`.
    fn seal(message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        let (cipher_key, mac_key) = (&key[..C::KEY_LEN], &key[C::KEY_LEN..]);
        let mut ciphertext = message.to_vec();
        C::seal_or_open(&mut ciphertext, nonce, cipher_key);

        CipherOutput {
            mac: M::digest(mac_key, &ciphertext),
            ciphertext,
        }
    }

    /// Works as follows:
    ///
    /// 1. Split the key into `cipher_key` (first bytes of the key) and `mac_key`
    ///   (remaining bytes).
    /// 2. Compute MAC over the ciphertext with `mac_key`. If MAC is not equal to
    ///   the supplied one, return `None`.
    /// 3. Decrypt the ciphertext under the `cipher_key` and `nonce`.
    fn open(output: &mut [u8], enc: &CipherOutput, nonce: &[u8], key: &[u8]) -> Result<(), ()> {
        debug_assert_eq!(key.len(), Self::KEY_LEN);
        debug_assert_eq!(enc.mac.len(), Self::MAC_LEN);
        debug_assert_eq!(output.len(), enc.ciphertext.len());

        let (cipher_key, mac_key) = (&key[..C::KEY_LEN], &key[C::KEY_LEN..]);
        if !constant_time_eq(&M::digest(mac_key, &enc.ciphertext), &enc.mac) {
            return Err(());
        }

        output.copy_from_slice(&enc.ciphertext);
        C::seal_or_open(output, nonce, cipher_key);
        Ok(())
    }
}
