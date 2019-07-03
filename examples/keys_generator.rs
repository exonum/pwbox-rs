// Copyright 2019 The Exonum Team
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

//! Password-based encryption example for securely storing an Ed25519 keypair.
//! For simplicity, errors during processing lead to panics.

use exonum_sodiumoxide::crypto::sign::{
    convert_sk_to_pk, keypair_from_seed, PublicKey, SecretKey, Seed, SEEDBYTES,
};
use hex_buffer_serde::Hex;
use pwbox::{sodium::Sodium, ErasedPwBox, Eraser, RestoredPwBox, Suite};
use rand::thread_rng;
use serde_derive::*;

use std::{borrow::Cow, env::args};

enum PublicKeyHex {}

impl Hex<PublicKey> for PublicKeyHex {
    fn create_bytes(value: &PublicKey) -> Cow<[u8]> {
        Cow::Borrowed(&value.0)
    }

    fn from_bytes(bytes: &[u8]) -> Result<PublicKey, String> {
        PublicKey::from_slice(bytes).ok_or_else(|| "invalid public key".to_owned())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair<T> {
    #[serde(with = "PublicKeyHex")]
    public_key: PublicKey,
    secret_key: T,
}

impl Keypair<ErasedPwBox> {
    pub fn restore(&self, eraser: &Eraser) -> Keypair<RestoredPwBox> {
        assert_eq!(
            self.secret_key.len(),
            SEEDBYTES,
            "incorrect length of encrypted data"
        );

        Keypair {
            public_key: self.public_key,
            secret_key: eraser.restore(&self.secret_key).unwrap(),
        }
    }
}

impl Keypair<RestoredPwBox> {
    pub fn decrypt(&self, password: impl AsRef<[u8]>) -> Keypair<SecretKey> {
        let mut seed = Seed([0; SEEDBYTES]);
        // `seed` is zeroed on drop, so we can use `PwBox::open_into`.
        self.secret_key.open_into(&mut seed.0, password).unwrap();
        let (public_key, secret_key) = keypair_from_seed(&seed);
        assert_eq!(
            public_key, self.public_key,
            "restored secret key does not match public key"
        );

        Keypair {
            public_key: self.public_key,
            secret_key,
        }
    }
}

impl Keypair<SecretKey> {
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = convert_sk_to_pk(&secret_key);
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn encrypt(&self, password: impl AsRef<[u8]>, eraser: &Eraser) -> Keypair<ErasedPwBox> {
        let seed = &self.secret_key[..SEEDBYTES];
        let pwbox = Sodium::build_box(&mut thread_rng())
            .seal(password, seed)
            .unwrap();
        let pwbox = eraser.erase(&pwbox).unwrap();

        Keypair {
            public_key: self.public_key,
            secret_key: pwbox,
        }
    }
}

fn main() {
    // Initialize an `Eraser` instance together with a `sodium` cryptosuite.
    let mut eraser = Eraser::new();
    eraser.add_suite::<Sodium>();

    let sk = args().nth(1).expect("You should to provide a SecretKey");
    let passphrase = args().nth(2).expect("You should to provide a passphrase");
    let secret_key =
        SecretKey::from_slice(&hex::decode(sk).unwrap()).expect("Wrong format of the SecretKey");

    // Create a random keypair from seed.
    let keypair = Keypair::new(secret_key);

    // Serialize the keypair into TOML.
    let keypair = keypair.encrypt(passphrase.as_str(), &eraser);
    let toml = toml::to_string_pretty(&keypair).unwrap();
    println!("{}", toml);
}
