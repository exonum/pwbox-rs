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

//! Test suite for different supported serialization formats.

extern crate pwbox;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate rand;
extern crate toml;

use pwbox::{rcrypto::RustCrypto, sodium::Sodium, ErasedPwBox, Eraser, Suite};
use rand::{thread_rng, Rng};

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn json_serialization_compatibility() {
    // Taken from `go-ethereum` keystore test vectors:
    // <https://github.com/ethereum/go-ethereum/blob/2714e8f091117b4f110198008348bfc19233ed60/
    //     accounts/keystore/testdata/keystore/aaa>
    const JSON: &str = r#"{
        "cipher": "aes-128-ctr",
        "ciphertext": "cb664472deacb41a2e995fa7f96fe29ce744471deb8d146a0e43c7898c9ddd4d",
        "cipherparams": { "iv": "dfd9ee70812add5f4b8f89d0811c9158" },
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32, "n": 8, "p": 16, "r": 8,
            "salt": "0d6769bf016d45c479213990d6a08d938469c4adad8a02ce507b4a4e7b7739f1"
        },
        "mac": "bac9af994b15a45dd39669fc66f9aa8a3b9dd8c22cb16e4d8d7ea089d0f1a1a9"
    }"#;

    const PASSWORD: &str = "foobar";

    let mut eraser = Eraser::new();
    eraser.add_suite::<RustCrypto>();
    let erased: ErasedPwBox = serde_json::from_str(JSON).unwrap();
    assert!(eraser.restore(&erased).unwrap().open(PASSWORD).is_ok());
}

#[test]
fn toml_serialization() {
    let mut rng = thread_rng();
    let secret: [u8; 32] = rng.gen();

    let mut eraser = Eraser::new();
    eraser.add_suite::<Sodium>();
    let encrypted = Sodium::build_box(&mut rng).seal(PASSWORD, &secret).unwrap();
    let encrypted = eraser.erase(encrypted).unwrap();

    let s = toml::to_string_pretty(&encrypted).unwrap();
    let restored = toml::from_str(&s).unwrap();
    let restored = eraser.restore(&restored).unwrap();
    assert_eq!(secret, &*restored.open(PASSWORD).unwrap());
}

#[test]
fn toml_deserialization_inner() {
    use pwbox::Error;

    const TOML: &str = r#"
        some_data = 5
        other_data = 'foobar'

        [key]
        ciphertext = 'cd9d2fb2355d8c60d92dcc860abc0c4b20ddd12dd52a4dd53caca0a2f87f7f5f'
        mac = '83ae22646d7834f254caea78862eafda'
        kdf = 'scrypt-nacl'
        cipher = 'xsalsa20-poly1305'

        [key.kdfparams]
        salt = '87d68fb57d9c2331cf2bd9fdd7551057798bd36d0d2999481311cfae39863691'
        memlimit = 16777216
        opslimit = 524288

        [key.cipherparams]
        iv = 'db39c466e2f8ae7fbbc857df48d99254017b059624af7106'
    "#;

    #[derive(Deserialize)]
    struct Test<T> {
        some_data: u64,
        other_data: Option<String>,
        key: T,
    }

    impl Test<ErasedPwBox> {
        fn open(self, eraser: &Eraser, password: &str) -> Result<Test<Vec<u8>>, Error> {
            Ok(Test {
                some_data: self.some_data,
                other_data: self.other_data,
                key: eraser.restore(&self.key)?.open(password)?.to_vec(),
            })
        }
    }

    let mut eraser = Eraser::new();
    eraser.add_suite::<Sodium>();
    let test: Test<ErasedPwBox> = toml::from_str(TOML).unwrap();
    let decrypted_test = test.open(&eraser, PASSWORD).unwrap();
    assert_eq!(decrypted_test.key.len(), 32);
}
