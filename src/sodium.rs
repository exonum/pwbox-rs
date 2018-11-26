//! Crypto primitives based on `libsodium`.

extern crate exonum_sodiumoxide as sodiumoxide;

use self::sodiumoxide::crypto::{
    pwhash::{
        self, derive_key, MemLimit, OpsLimit, Salt, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE,
    },
    secretbox::{self, open_detached, seal_detached, Key, Nonce, Tag},
};
use failure::Fail;

use super::{Cipher, CipherOutput, DeriveKey};
use erased::{Eraser, Suite};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scrypt {
    pub opslimit: u32,
    pub memlimit: u32,
}

impl Default for Scrypt {
    fn default() -> Self {
        Scrypt {
            opslimit: OPSLIMIT_INTERACTIVE.0 as u32,
            memlimit: MEMLIMIT_INTERACTIVE.0 as u32,
        }
    }
}

impl Scrypt {
    pub fn light() -> Self {
        Scrypt {
            opslimit: 3 << 18,
            memlimit: 1 << 22,
        }
    }
}

#[derive(Debug, Fail)]
#[fail(display = "out of memory")]
struct ScryptError;

impl DeriveKey for Scrypt {
    fn salt_len(&self) -> usize {
        pwhash::SALTBYTES
    }

    fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        buf: &mut [u8],
    ) -> Result<(), Box<dyn Fail>> {
        derive_key(
            buf,
            password.as_ref(),
            &Salt::from_slice(salt).expect("invalid salt length"),
            OpsLimit(self.opslimit as usize),
            MemLimit(self.memlimit as usize),
        ).map(drop)
        .map_err(|()| Box::new(ScryptError) as Box<dyn Fail>)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct XSalsa20Poly1305;

impl Cipher for XSalsa20Poly1305 {
    fn key_len(&self) -> usize {
        secretbox::KEYBYTES
    }

    fn nonce_len(&self) -> usize {
        secretbox::NONCEBYTES
    }

    fn mac_len(&self) -> usize {
        secretbox::MACBYTES
    }

    fn seal(&self, message: &[u8], nonce: &[u8], key: &[u8]) -> CipherOutput {
        let nonce = Nonce::from_slice(nonce).expect("nonce");
        let key = Key::from_slice(key).expect("key");
        let mut message = message.to_vec();

        let Tag(mac) = seal_detached(&mut message, &nonce, &key);
        CipherOutput {
            ciphertext: message,
            mac: mac.to_vec(),
        }
    }

    fn open(&self, enc: &CipherOutput, nonce: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce).expect("invalid nonce length");
        let key = Key::from_slice(key).expect("invalid key length");
        let mac = Tag::from_slice(&enc.mac).expect("invalid MAC length");
        let mut message = enc.ciphertext.clone();

        open_detached(&mut message, &mac, &nonce, &key)
            .map(|()| message)
            .ok()
    }
}

#[test]
fn basics() {
    use rand::thread_rng;
    use PwBox;

    const PASSWORD: &str = "correct horse battery staple";
    const MESSAGE: &[u8] = b"foobar";

    let pwbox =
        PwBox::<Scrypt, XSalsa20Poly1305>::new(&mut thread_rng(), PASSWORD, MESSAGE).unwrap();

    assert_eq!(pwbox.open(PASSWORD).expect("pwbox.open"), MESSAGE.to_vec());
}

#[derive(Debug)]
pub enum Sodium {}

impl Suite for Sodium {
    type Cipher = XSalsa20Poly1305;
    type DeriveKey = Scrypt;

    fn add_ciphers_and_kdfs(eraser: &mut Eraser) {
        eraser
            .add_kdf::<Scrypt>("scrypt-nacl")
            .add_cipher::<XSalsa20Poly1305>("xsalsa20-poly1305");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {erased::test_kdf_and_cipher_corruption, test_kdf_and_cipher};

    #[test]
    fn scrypt_and_salsa() {
        let scrypt = Scrypt::light();
        test_kdf_and_cipher::<_, XSalsa20Poly1305>(scrypt);
    }

    #[test]
    fn scrypt_and_salsa_corruption() {
        let scrypt = Scrypt::light();
        test_kdf_and_cipher_corruption::<_, XSalsa20Poly1305>(scrypt);
    }
}
