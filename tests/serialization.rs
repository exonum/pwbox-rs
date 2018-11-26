//! Test suite for different supported serialization formats.

extern crate pwbox;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rand;
extern crate toml;

use pwbox::{sodium::Sodium, ErasedPwBox, Eraser, Suite};
use rand::{thread_rng, Rng};

const PASSWORD: &str = "correct horse battery staple";

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
    assert_eq!(restored.open(PASSWORD).unwrap(), secret);
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
                key: eraser.restore(&self.key)?.open(password)?,
            })
        }
    }

    let mut eraser = Eraser::new();
    eraser.add_suite::<Sodium>();
    let test: Test<ErasedPwBox> = toml::from_str(TOML).unwrap();
    let decrypted_test = test.open(&eraser, PASSWORD).unwrap();
    assert_eq!(decrypted_test.key.len(), 32);
}
