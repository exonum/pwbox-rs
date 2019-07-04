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

use failure::{bail, format_err, Error};
use pwbox::{sodium::Sodium, ErasedPwBox, Eraser, Suite};
use rand::thread_rng;
use rpassword::read_password_from_tty;
use structopt::StructOpt;

use pwbox::sodium::Scrypt;
use std::{
    env::{self, VarError},
    fs,
    io::{self, Read},
    str::FromStr,
};

const HELP: &str =
    "Simple key management utility, allowing to encrypt and decrypt arbitrary bytes.";

fn parse_scrypt(s: &str) -> Result<Scrypt, Error> {
    Ok(match s {
        "light" | "M" => Scrypt::light(),
        "interactive" | "L" => Scrypt::interactive(),
        "sensitive" | "XL" => Scrypt::sensitive(),
        _ => bail!("Invalid scrypt setting"),
    })
}

#[derive(Debug, StructOpt)]
struct PassphraseArgs {
    /// Source to get the passphrase from. Allowed values are `tty` (read interactively from TTY),
    /// `pass:$pass` (pass the passphrase directly)
    ///  and `env:$var` (use env variable with name `$var`).
    #[structopt(name = "pass", long, short, default_value = "tty")]
    source: PassphraseSource,
}

#[derive(Debug)]
enum PassphraseSource {
    Tty,
    Value(String),
    Env(String),
}

impl FromStr for PassphraseSource {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tty" => Ok(PassphraseSource::Tty),
            s if s.starts_with("pass:") => Ok(PassphraseSource::Value(s[5..].to_owned())),
            s if s.starts_with("env:") => Ok(PassphraseSource::Env(s[4..].to_owned())),
            _ => bail!("Invalid passphrase spec"),
        }
    }
}

impl PassphraseSource {
    fn get_passphrase(self) -> Result<String, Error> {
        match self {
            PassphraseSource::Value(passphrase) => Ok(passphrase),

            PassphraseSource::Env(var_name) => {
                let passphrase = env::var(&var_name).map_err(|e| match e {
                    VarError::NotPresent => format_err!(
                        "Env variable `{}` is not set \
                         (should contain encryption passphrase)",
                        var_name
                    ),
                    VarError::NotUnicode(_) => {
                        format_err!("Cannot decode encryption passphrase from env variable")
                    }
                })?;

                Ok(passphrase)
            }

            PassphraseSource::Tty => {
                read_password_from_tty(Some("Enter passphrase: ")).map_err(Into::into)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PointerComponent<'a> {
    Index(usize),
    Name(&'a str),
}

impl<'a> PointerComponent<'a> {
    fn from_str(s: &'a str) -> Vec<Self> {
        s.split('.')
            .filter_map(|raw_component| {
                if raw_component.is_empty() {
                    None
                } else {
                    Some(
                        raw_component
                            .parse::<usize>()
                            .map(PointerComponent::Index)
                            .unwrap_or_else(|_| PointerComponent::Name(raw_component)),
                    )
                }
            })
            .collect()
    }

    fn traverse<'v>(mut object: &'v toml::Value, pointer: &[Self]) -> Option<&'v toml::Value> {
        for component in pointer {
            object = match component {
                PointerComponent::Index(index) => object.get(index)?,
                PointerComponent::Name(name) => object.get(name)?,
            };
        }
        Some(object)
    }
}

#[structopt(
    name = "Simple key util",
    raw(after_help = "HELP", set_term_width = "80")
)]
#[derive(Debug, StructOpt)]
enum Args {
    /// Encrypts data with a passphrase
    #[structopt(name = "enc")]
    Encrypt {
        /// Hex-encoded data to encrypt.
        #[structopt(name = "data")]
        data: String,

        /// Scrypt setting to use. Allowed values are `light`, `interactive`, or `sensitive`,
        /// also accessible by aliases `M`, `L` and `XL`.
        #[structopt(
            name = "scrypt",
            long,
            short,
            parse(try_from_str = "parse_scrypt"),
            default_value = "interactive"
        )]
        scrypt: Scrypt,

        #[structopt(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Decrypts data using a passphrase
    #[structopt(name = "dec")]
    Decrypt {
        /// File to read the encrypted key from. Use `-` to read from stdin.
        #[structopt(name = "file")]
        file: String,

        /// Pointer to the key in the file in the format `foo.1.bar`.
        #[structopt(name = "ptr", long, short = "@", default_value = "")]
        pointer: String,

        /// Print `OK` on success instead of outputting the secret.
        #[structopt(name = "check", long, short)]
        check: bool,

        #[structopt(flatten)]
        passphrase: PassphraseArgs,
    },
}

impl Args {
    fn execute(self) -> Result<(), Error> {
        // Initialize an `Eraser` instance together with a `sodium` cryptosuite.
        let mut eraser = Eraser::new();
        eraser.add_suite::<Sodium>();

        match self {
            Args::Encrypt {
                data,
                scrypt,
                passphrase,
            } => {
                let data = hex::decode(data)?;
                let passphrase = passphrase.source.get_passphrase()?;
                let encrypted = Sodium::build_box(&mut thread_rng())
                    .kdf(scrypt)
                    .seal(&passphrase, &data)?;
                let encrypted = eraser.erase(&encrypted)?;
                println!("{}", toml::to_string_pretty(&encrypted)?);
            }

            Args::Decrypt {
                file,
                pointer,
                check,
                passphrase,
            } => {
                let input = if file == "" || file == "-" {
                    let mut buffer = vec![];
                    io::stdin().read_to_end(&mut buffer)?;
                    buffer
                } else {
                    fs::read(&file)?
                };

                let pointer = PointerComponent::from_str(&pointer);
                let toml_object: toml::Value = toml::from_slice(&input)?;
                let encrypted = PointerComponent::traverse(&toml_object, &pointer)
                    .ok_or_else(|| format_err!("Specified path does not exist in the input"))?;

                let encrypted: ErasedPwBox = encrypted.clone().try_into()?;
                let passphrase = passphrase.source.get_passphrase()?;
                let data = eraser.restore(&encrypted)?.open(&passphrase)?;
                if check {
                    println!("OK")
                } else {
                    println!("{}", hex::encode(&data[..]));
                }
            }
        }

        Ok(())
    }
}

fn main() -> Result<(), Error> {
    Args::from_args().execute()
}
