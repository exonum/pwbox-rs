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
use smallvec::SmallVec;

use std::{fmt, ops::Deref};

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

#[cfg(feature = "rust-crypto")]
pub mod log_transform {
    use serde::{de::Visitor, Deserializer, Serializer};

    use std::fmt;

    pub enum LogNTransform {}

    #[cfg(feature = "rust-crypto")]
    impl LogNTransform {
        #[cfg_attr(feature = "cargo-clippy", allow(trivially_copy_pass_by_ref))]
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

    #[test]
    fn log2_transform() {
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
}
