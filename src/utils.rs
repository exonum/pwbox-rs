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
