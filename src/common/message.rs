use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::Secp256k1;
use rand::{thread_rng,Rng};

use crate::common::crypto::{from_hex, to_hex};
use crate::common::{ErrorKind, Error};
use crate::contacts::GrinboxAddress;

use grin_wallet_impls::encrypt;
use std::num::NonZeroU32;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    #[serde(default)]
    pub destination: Option<GrinboxAddress>,
    encrypted_message: String,
    salt: String,
    nonce: String,
}

// See comments at  mwc-wallet/impls/src/seed.rs
// Seed is encrypted exactlty the same way ...

impl EncryptedMessage {
    pub fn new(
        message: String,
        destination: &GrinboxAddress,
        receiver_public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> Result<EncryptedMessage, Error> {
        let secp = Secp256k1::new();
        let mut common_secret = receiver_public_key.clone();
        common_secret
            .mul_assign(&secp, secret_key)
            .map_err(|e| ErrorKind::Encryption(format!("Keys pair doesn't match, {}",e)))?;
        let common_secret_ser = common_secret.serialize_vec(&secp, true);
        let common_secret_slice = &common_secret_ser[1..33];

        let salt: [u8; 8] = thread_rng().gen();
        let nonce: [u8; 12] = thread_rng().gen();
        let mut key = [0; 32];
        ring::pbkdf2::derive(&ring::digest::SHA512, NonZeroU32::new(100).unwrap(), &salt, common_secret_slice, &mut key);
        let mut enc_bytes = message.as_bytes().to_vec();
        let suffix_len = encrypt::aead::CHACHA20_POLY1305.tag_len();
        for _ in 0..suffix_len {
            enc_bytes.push(0);
        }
        let sealing_key = encrypt::aead::SealingKey::new(&encrypt::aead::CHACHA20_POLY1305, &key)
            .map_err(|e| ErrorKind::Encryption(format!("Unable to create sealing key, {}",e)))?;
        encrypt::aead::seal_in_place(&sealing_key, &nonce, &[], &mut enc_bytes, suffix_len)
            .map_err(|e| ErrorKind::Encryption(format!("Unable to seal the data, {}",e)))?;

        Ok(EncryptedMessage {
            destination: Some(destination.clone()),
            encrypted_message: to_hex(enc_bytes),
            salt: to_hex(salt.to_vec()),
            nonce: to_hex(nonce.to_vec()),
        })
    }

    pub fn key(&self, sender_public_key: &PublicKey, secret_key: &SecretKey) -> Result<[u8; 32], Error> {
        let salt = from_hex(self.salt.clone())
            .map_err(|e| ErrorKind::Decryption(format!("Salt is not in HEX, {}", e)))?;

        let secp = Secp256k1::new();
        let mut common_secret = sender_public_key.clone();
        common_secret
            .mul_assign(&secp, secret_key)
            .map_err(|e| ErrorKind::Decryption(format!("Keys pair doesn't match, {}",e)))?;
        let common_secret_ser = common_secret.serialize_vec(&secp, true);
        let common_secret_slice = &common_secret_ser[1..33];

        let mut key = [0; 32];
        ring::pbkdf2::derive(&ring::digest::SHA512, NonZeroU32::new(100).unwrap(), &salt, common_secret_slice, &mut key);

        Ok(key)
    }

    pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<String, Error> {
        let mut encrypted_message = from_hex(self.encrypted_message.clone())
            .map_err(|e| ErrorKind::Decryption(format!("Uncrypted message is not in HEX, {}", e)))?;
        let nonce = from_hex(self.nonce.clone())
            .map_err(|e| ErrorKind::Decryption(format!("Nonce is not in HEX, {}", e)))?;

        let opening_key = encrypt::aead::OpeningKey::new(&encrypt::aead::CHACHA20_POLY1305, key)
            .map_err(|e| ErrorKind::Decryption(format!("Unable to create sealing key, {}",e)))?;
        let decrypted_data =
            encrypt::aead::open_in_place(&opening_key, &nonce, &[], 0, &mut encrypted_message)
                .map_err(|e| ErrorKind::Decryption(format!("Unable to seal the data, {}",e)))?;
        String::from_utf8(decrypted_data.to_vec()).map_err(|e| ErrorKind::Decryption(format!("Decryption result to HEX conversion error, {}", e)).into())
    }
}
