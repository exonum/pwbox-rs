use serde::{de::Visitor, Deserializer, Serializer};

use std::fmt;

pub enum HexBytes {}

impl HexBytes {
    pub fn serialize<S: Serializer>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(value))
        } else {
            serializer.serialize_bytes(value)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as DeError;

        struct HexVisitor;

        impl<'de> Visitor<'de> for HexVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("hex-encoded byte array")
            }

            fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
                hex::decode(value).map_err(E::custom)
            }

            fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
                hex::decode(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(HexVisitor)
    }
}

#[cfg(feature = "rust-crypto")]
pub enum LogNTransform {}

#[cfg(feature = "rust-crypto")]
impl LogNTransform {
    pub fn serialize<S: Serializer>(value: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        assert!(*value < 32, "too large value to serialize: {}", value);
        serializer.serialize_u64(1 << (*value as u64))
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

#[cfg(feature = "rust-crypto")]
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
