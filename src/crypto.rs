use std::error::Error;

use base64::Engine;
use openssl::symm::{Cipher, Crypter, Mode};

pub fn decrypt_config(encrypted: &str, secret: &str) -> Result<String, Box<dyn Error>> {
    // Step 1: Base64 decode
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted.replace("\n", "").replace(" ", ""))
        .unwrap();

    // Step 2: Verify prefix
    assert!(&data[0..8] == b"Salted__");
    let salt = &data[8..16];
    let encrypted = &data[16..];

    // Step 3: Derive key and iv using PBKDF2-HMAC-SHA256
    let mut key = [0u8; 32]; // AES-256 => 32-byte key
    let mut iv = [0u8; 16]; // CBC IV
    let mut derived = [0u8; 48]; // key + iv = 48 bytes total

    openssl::pkcs5::pbkdf2_hmac(
        secret.as_bytes(),
        salt,
        10_000,
        openssl::hash::MessageDigest::sha256(),
        &mut derived,
    )
    .unwrap();
    key.copy_from_slice(&derived[..32]);
    iv.copy_from_slice(&derived[32..48]);

    // Step 4: Decrypt
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).unwrap();
    crypter.pad(true);

    let mut plaintext = vec![0; encrypted.len() + cipher.block_size()];
    let mut count = crypter.update(encrypted, &mut plaintext).unwrap();
    count += crypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);

    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::NetworkConfig;

    #[tokio::test]
    async fn test_decrypt_config() {
        // cat servers.json | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass pass:wg-multizone
        let mut r = r#"
            U2FsdGVkX1/yCvhJaU9iPq+ei2yy3AebTbqBByZH+o5Q75eyWhbOkelF1ON2elCq
            RN07JlKorWX1O5FJeoeNud4ciwT/KUcnDnTIZWVSmni3gMpDhOcvl4otQqS48pwt
            hVUQkbuhtqiThOFBOmRPLEc7h0A6z+rkKngPWoyDuRak04DH18XpHFUdwCoGc75F
            fOerWTS5sLBHcaQzxf2qeeBr0jkcQqVWPkjMyHYDhR8YV4Kk8XOSXw6cfmICbeJl
            7P9+qwzZSJz4n2PNqjYz8A=="#
            .replace("\n", "")
            .replace(" ", "");
        r = decrypt_config(&r, "wg-multizone").unwrap();
        println!("{}", r);
        let r: NetworkConfig = serde_json::from_str(&r).unwrap();
        println!("{:?}", r);
    }
}
