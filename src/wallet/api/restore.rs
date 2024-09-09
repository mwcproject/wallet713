// Copyright 2018 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Functions to restore a wallet's outputs from just the master seed

use crate::common::Error;
use grin_util::secp::key::PublicKey;
use grin_wallet_impls::keychain::Keychain;
use grin_wallet_libwallet::proof::crypto::Hex;
use grin_wallet_libwallet::{NodeClient, WalletBackend};
use std::fs::OpenOptions;

struct PubKeyInfo {
    pub_key_hex: String,
    rewind_hash: std::vec::Vec<u8>, // rewind_hash from the public key
}

/// Check / repair wallet contents
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn scan_outputs<'a, T: ?Sized, C, K>(
    wallet: &mut T,
    pub_keys: Vec<PublicKey>,
    output_fn: String,
) -> Result<(), Error>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
{
    use blake2_rfc::blake2b::blake2b;
    use grin_util::secp::key::SecretKey;
    use grin_util::secp::{ContextFlag, Secp256k1};
    use std::io::prelude::*;

    // First, get a definitive list of outputs we own from the chain
    println!("Starting scan outputs.");

    let batch_size = 1000;
    let mut start_index = 1;

    let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);

    // Calculate rewind_hash for the commit.
    let pub_keys_info: Vec<PubKeyInfo> = pub_keys
        .iter()
        .map(|pk: &PublicKey| {
            let public_root_key = pk.serialize_vec(&secp, true);
            let rewind_hash = blake2b(32, &[], &public_root_key[..]).as_bytes().to_vec();
            let pub_key_hex = pk.to_hex();

            PubKeyInfo {
                pub_key_hex,
                rewind_hash,
            }
        })
        .collect();

    // We founf output that match one of the public key.
    // Result will be appended into the file...
    let mut result_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(output_fn)?;

    loop {
        let (highest_index, last_retrieved_index, outputs) = wallet
            .w2n_client()
            .get_outputs_by_pmmr_index(start_index, None, batch_size)?;
        println!(
            "Scanning {} outputs, up to index {}. (Highest index: {})",
            outputs.len(),
            highest_index,
            last_retrieved_index,
        );

        // Scanning outputs
        for output in outputs.iter() {
            let (commit, proof, _, height, mmr_index) = output;

            // Apply public keys that we have
            for pk_info in &pub_keys_info {
                // Not processing 'legacy' logic. It is ok to test all commits. Naturally will skip 'non public' ones
                //   Legacy logic try to hadble the latest data similar way, it is extra for scanning
                let res = blake2b(32, &commit.0, &pk_info.rewind_hash);
                let nonce = SecretKey::from_slice(&secp, res.as_bytes()).map_err(|e| {
                    Error::GenericError(format!("error: Unable to create nonce: {}", e))
                })?;

                let info = secp.rewind_bullet_proof(*commit, nonce.clone(), None, *proof);
                if info.is_err() {
                    continue;
                }

                let info = info.unwrap();
                result_file.write_fmt(format_args!(
                    "PublicKey={} Commit={} amount={} height={} mmr_index={}\n",
                    pk_info.pub_key_hex,
                    commit.to_hex(),
                    info.value,
                    height,
                    mmr_index
                ))?;
                // Note, proof at this moment is totally valid. We are not checking the proof because the network already did that.
                // No reasons to be so paranoid.
            }
        }

        if highest_index == last_retrieved_index {
            break;
        }
        start_index = last_retrieved_index + 1;
    }

    Ok(())
}
