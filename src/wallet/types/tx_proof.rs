use grin_util::secp::key::SecretKey;
use grin_util::secp::pedersen::Commitment;
use grin_util::secp::Signature;

use crate::common::crypto::verify_signature;
use crate::common::crypto::Hex;
use crate::common::message::EncryptedMessage;
use crate::contacts::{Address, GrinboxAddress};
use grin_wallet_libwallet::Slate;
use std::{path, fs};
use crate::common::Error;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use common::ErrorKind;

pub const TX_PROOF_SAVE_DIR: &'static str = "saved_proofs";

#[derive(Debug, Serialize, Deserialize)]
pub struct TxProof {
    pub address: GrinboxAddress,
    pub message: String,
    pub challenge: String,
    pub signature: Signature,
    pub key: [u8; 32],
    pub amount: u64,
    pub fee: u64,
    pub inputs: Vec<Commitment>,
    pub outputs: Vec<Commitment>,
}

impl TxProof {
    pub fn verify_extract(
        &self,
        expected_destination: Option<&GrinboxAddress>,
    ) -> Result<(Option<GrinboxAddress>, Slate), ErrorKind> {
        let mut challenge = String::new();
        challenge.push_str(self.message.as_str());
        challenge.push_str(self.challenge.as_str());

        let public_key = self
            .address
            .public_key()
            .map_err(|_| ErrorKind::TxProofParsePublicKey)?;

        verify_signature(&challenge, &self.signature, &public_key)
            .map_err(|_| ErrorKind::TxProofVerifySignature)?;

        let encrypted_message: EncryptedMessage =
            serde_json::from_str(&self.message).map_err(|_| ErrorKind::TxProofParseEncryptedMessage)?;

        // TODO: at some point, make this check required
        let destination = encrypted_message.destination.clone();

        if destination.is_some()
            && expected_destination.is_some()
            && destination.as_ref().unwrap().public_key != expected_destination.unwrap().public_key
        {
            return Err(ErrorKind::TxProofVerifyDestination);
        }

        let decrypted_message = encrypted_message
            .decrypt_with_key(&self.key)
            .map_err(|_| ErrorKind::TxProofDecryptMessage)?;

        let slate = Slate::deserialize_upgrade(&decrypted_message)
            .map_err(|e| ErrorKind::TxProofParseSlate(format!("{}",e)))?;

        Ok((destination, slate))
    }

    pub fn from_response(
        from: String,
        message: String,
        challenge: String,
        signature: String,
        secret_key: &SecretKey,
        expected_destination: Option<&GrinboxAddress>,
    ) -> Result<(Slate, TxProof), ErrorKind> {
        let address =
            GrinboxAddress::from_str(from.as_str()).map_err(|_| ErrorKind::TxProofParseAddress(from) )?;
        let signature =
            Signature::from_hex(signature.as_str()).map_err(|_| ErrorKind::TxProofParseSignature(signature))?;
        let public_key = address
            .public_key()
            .map_err(|_| ErrorKind::TxProofParsePublicKey)?;
        let encrypted_message: EncryptedMessage =
            serde_json::from_str(&message).map_err(|_| ErrorKind::TxProofParseEncryptedMessage)?;
        let key = encrypted_message
            .key(&public_key, secret_key)
            .map_err(|_| ErrorKind::TxProofDecryptionKey)?;

        let proof = TxProof {
            address,
            message,
            challenge,
            signature,
            key,
            amount: 0,
            fee: 0,
            inputs: vec![],
            outputs: vec![],
        };

        let (_, slate) = proof.verify_extract(expected_destination)?;

        Ok((slate, proof))
    }

    // Here is a backend layer. Putting it here because mwc713 is using mwc-wallet backend.
    // We don't want to move Proof for the mwc-wallet becuase it is mwc713 specific code

    pub fn init_proof_backend(data_file_dir: &str) -> Result<(), Error> {
        let stored_tx_proof_path = path::Path::new(data_file_dir).join(TX_PROOF_SAVE_DIR);
        fs::create_dir_all(&stored_tx_proof_path)
            .expect("Couldn't create wallet backend tx proof storage directory!");
        Ok(())
    }

    pub fn has_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<bool, Error> {
        let filename = format!("{}.proof", uuid);
        let path = path::Path::new(data_file_dir)
            .join(TX_PROOF_SAVE_DIR)
            .join(filename);
        let tx_proof_file = Path::new(&path).to_path_buf();
        Ok(tx_proof_file.exists())
    }

    /// Read stored proof file. data_file_dir
    pub fn get_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<TxProof, Error> {
        let filename = format!("{}.proof", uuid);
        let path = path::Path::new(data_file_dir)
            .join(TX_PROOF_SAVE_DIR)
            .join(filename);
        let tx_proof_file = Path::new(&path).to_path_buf();
        if !tx_proof_file.exists() {
            return Err(crate::common::ErrorKind::TransactionHasNoProof.into());
        }
        let mut tx_proof_f = File::open(tx_proof_file)?;
        let mut content = String::new();
        tx_proof_f.read_to_string(&mut content)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn store_tx_proof(&self, data_file_dir: &str, uuid: &str) -> Result<(), Error> {
        let filename = format!("{}.proof", uuid);
        let path = path::Path::new(data_file_dir)
            .join(TX_PROOF_SAVE_DIR)
            .join(filename);
        let path_buf = Path::new(&path).to_path_buf();
        let mut stored_tx = File::create(path_buf)?;
        let proof_ser = serde_json::to_string(self)?;
        stored_tx.write_all(&proof_ser.as_bytes())?;
        stored_tx.sync_all()?;
        Ok(())
    }

}
