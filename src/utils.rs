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

use clear_on_drop::ClearOnDrop;
use serde::{de::Visitor, Deserializer, Serializer};
use serde_derive::*;
use smallvec::{smallvec, SmallVec};

use core::{fmt, ops::Deref};

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
    pub(crate) fn zeros(len: usize) -> Self {
        SensitiveData(smallvec![0; len])
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut *self.0
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

enum LogNTransform {}

impl LogNTransform {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(value: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        assert!(*value < 32, "too large value to serialize: {}", value);
        serializer.serialize_u64(1 << u64::from(*value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as DeError;

        struct Log2Visitor;

        impl<'de> Visitor<'de> for Log2Visitor {
            type Value = u8;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a power of two")
            }

            fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
                if !value.is_power_of_two() {
                    return Err(E::custom("not a power of two"));
                }
                Ok(63 - value.leading_zeros() as u8)
            }
        }

        deserializer.deserialize_u64(Log2Visitor)
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
pub struct ScryptParams {
    #[serde(rename = "n", with = "LogNTransform")]
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) p: u32,
}

impl Default for ScryptParams {
    /// Returns the "interactive" `scrypt` parameters as defined in libsodium.
    ///
    /// ```text
    /// n = 2^14, r = 8, p = 1.
    /// ```
    fn default() -> Self {
        ScryptParams {
            log_n: 14,
            r: 8,
            p: 1,
        }
    }
}

impl ScryptParams {
    /// Returns "light" `scrypt` parameters as used in Ethereum keystore implementations.
    ///
    /// ```text
    /// n = 2^12, r = 8, p = 6.
    /// ```
    pub const fn light() -> Self {
        ScryptParams {
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
        ScryptParams { log_n, p, r: 8 }
    }
}

#[test]
fn log2_transform() {
    use serde_derive::*;
    use serde_json::{self, Value};

    #[derive(Serialize, Deserialize)]
    struct Test {
        #[serde(rename = "n", with = "LogNTransform")]
        log_n: u8,
    }

    let json = r#"{ "n": 65536 }"#;
    let value: Test = serde_json::from_str(json).unwrap();
    assert_eq!(value.log_n, 16);
    assert_eq!(
        serde_json::to_value(value).unwrap(),
        serde_json::from_str::<Value>(json).unwrap(),
    );
}
