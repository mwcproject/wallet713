use std::collections::{HashSet, HashMap};
use uuid::Uuid;

pub use grin_util::secp::{Message};
use common::crypto::{Hex, SecretKey};
use grin_core::core::hash::{Hash};
use grin_core::ser;
use grin_util::secp::pedersen;
use grin_util::secp::{ContextFlag, Secp256k1, Signature};
use grin_p2p::types::PeerInfoDisplay;

use crate::contacts::GrinboxAddress;

//use super::keys;
use super::types::TxProof;
use grin_wallet_libwallet::{AcctPathMapping, BlockFees, CbData, NodeClient, Slate, TxLogEntry, TxWrapper, WalletInfo, WalletBackend, OutputCommitMapping, WalletInst, WalletLCProvider, StatusMessage, TxLogEntryType};
use grin_core::core::Transaction;
use grin_keychain::{Identifier, Keychain};
use grin_util::secp::key::{ PublicKey };
use crate::common::{Arc, Mutex, Error, ErrorKind};

use grin_keychain::{SwitchCommitmentType, ExtKeychainPath};
use grin_wallet_libwallet::internal::{updater,keys};
use std::sync::mpsc;
use crate::common::hasher;
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::fs::File;
use std::io::{Write, BufReader, BufRead};

// struct for sending back node information
pub struct NodeInfo
{
    pub height: u64,
    pub total_difficulty: u64,
    pub peers: Vec<PeerInfoDisplay>,
}

pub fn invoice_tx<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    active_account: Option<String>,
        slate: &Slate,
        address: Option<String>,
        minimum_confirmations: u64,
        max_outputs: u32,
        num_change_outputs: u32,
        selection_strategy_is_use_all: bool,
        message: Option<String>,
    ) -> Result< Slate, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
        wallet_lock!(wallet_inst, w);

        let params = grin_wallet_libwallet::InitTxArgs {
            src_acct_name: active_account,
            amount: slate.amount,
            minimum_confirmations,
            max_outputs,
            num_change_outputs,
            /// If `true`, attempt to use up as many outputs as
            /// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
            /// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
            /// minimizes fees. This will generally result in many inputs and a large change output(s),
            /// usually much larger than the amount being sent. If `false`, the transaction will include
            /// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
            /// value outputs.
            selection_strategy_is_use_all,
            message,
            /// Optionally set the output target slate version (acceptable
            /// down to the minimum slate version compatible with the current. If `None` the slate
            /// is generated with the latest version.
            target_slate_version: None,
            /// Number of blocks from current after which TX should be ignored
            ttl_blocks: None,
            /// If set, require a payment proof for the particular recipient
            payment_proof_recipient_address: None,
            address,
            /// If true, just return an estimate of the resulting slate, containing fees and amounts
            /// locked without actually locking outputs or creating the transaction. Note if this is set to
            /// 'true', the amount field in the slate will contain the total amount locked, not the provided
            /// transaction amount
            estimate_only: None,
            /// Sender arguments. If present, the underlying function will also attempt to send the
            /// transaction to a destination and optionally finalize the result
            send_args: None,
        };
        let slate = grin_wallet_libwallet::owner::process_invoice_tx(
            &mut **w,
            None,
            slate,
            params,
            false,
        )?;

        Ok(slate)
    }

    pub fn show_rootpublickey<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        message: Option<&str>
    )  -> Result<(), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let keychain = w.keychain(None)?;
        let root_pub_key = keychain.public_root_key().to_hex();

        cli_message!("Root public key: {}", root_pub_key);

        match message {
            Some(msg) => {
                // that path and type will give as the root private key
                let id = ExtKeychainPath::new(0,0,0,0,0).to_identifier();

                // Note, first 32 bytes of the message will be used...
                // Hash size equal to the message size (32 bytes).
                // Actually we could sign the message, not
                let msg_hash = Hash::from_vec(msg.as_bytes());
                let msg_message = Message::from_slice(msg_hash.as_bytes())?;

                // id pointes to the root key. Will check
                let signature = keychain.sign(&msg_message,0, &id, &SwitchCommitmentType::None)?;

                println!("Signature: {}", signature.to_hex());
            },
            None  => {}
        }
        Ok(())
    }

    pub fn verifysignature(
                message: &str,
                signature: &str,
                pubkey: &str
    ) -> Result<(), Error> {
        let msg = Hash::from_vec(message.as_bytes());
        let msg = Message::from_slice(msg.as_bytes())?;

        let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);
        let pk = grin_util::from_hex(pubkey.to_string())?;
        let pk = PublicKey::from_slice(&secp, &pk)?;

        let signature = grin_util::from_hex(signature.to_string())?;
        let signature = Signature::from_der(&secp, &signature)?;

        match secp.verify(&msg, &signature, &pk) {
            Ok(_) => println!("Message, signature and public key are valid!"),
            Err(_) => println!("WARNING: Message, signature and public key are INVALID!"),
        }
        Ok(())
    }

    pub fn getnextkey<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        amount: u64) -> Result<String, Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let id = keys::next_available_key(&mut **w, None)?;
        let keychain = w.keychain(None)?;
        let sec_key = keychain.derive_key(amount, &id, &SwitchCommitmentType::Regular)?;
        let pubkey = PublicKey::from_secret_key(keychain.secp(), &sec_key)?;
        let ret = format!("{:?}, {:?}", id, pubkey);
        Ok(ret)
    }

    pub fn accounts<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>
    ) -> Result<Vec<AcctPathMapping>, Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        Ok(keys::accounts(&mut **w)?)
    }

    pub fn create_account_path<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        label: &str
    ) -> Result<Identifier, Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        Ok(keys::new_acct_path(&mut **w, None, label)?)
    }

    pub fn rename_account_path<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        old_label: &str, new_label: &str
    ) -> Result<(), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let accounts = accounts(wallet_inst.clone())?;
        wallet_lock!(wallet_inst, w);
        keys::rename_acct_path(&mut **w, None, accounts, old_label, new_label)?;
        Ok(())
    }

   pub fn retrieve_tx_id_by_slate_id<'a, L, C, K>(
       wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
       slate_id: Uuid
   ) -> Result<u32, Error>
   where
           L: WalletLCProvider<'a, C, K>,
           C: NodeClient + 'a,
           K: Keychain + 'a,
   {
       wallet_lock!(wallet_inst, w);
       let tx = updater::retrieve_txs(&mut **w, None,
                                      None, Some(slate_id),
                                      None,
                                      false, None, None)?;
       let mut ret = 1000000000;
       for t in &tx {
           ret = t.id;
       }

       Ok(ret)
   }

    pub fn retrieve_outputs<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        include_spent: bool,
        refresh_from_node: bool,
        tx_id: Option<u32>,
        pagination_start: Option<u32>,
        pagination_len:   Option<u32>,
    ) -> Result<(bool, Vec<OutputCommitMapping>), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let parent_key_id = w.parent_key_id();

        let mut validated = false;
        if refresh_from_node {
            validated = update_outputs(&mut **w, false, None, None);
        }

        let res = Ok((
            validated,
            updater::retrieve_outputs(&mut **w,
                                      None,
                                      include_spent,
                                      tx_id,
                                      Some(&parent_key_id),
                                      pagination_start,
                                      pagination_len)?,
        ));

        //w.close()?;
        res
    }

    pub fn retrieve_txs<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        refresh_from_node: bool,
        tx_id: Option<u32>,
        tx_slate_id: Option<Uuid>,
    ) -> Result<(bool, Vec<TxLogEntry>), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let parent_key_id = w.parent_key_id();

        let mut validated = false;
        if refresh_from_node {
            validated = update_outputs(&mut **w, false, None, None);
        }

        let res = Ok((
            validated,
            updater::retrieve_txs(&mut **w, None, tx_id, tx_slate_id, Some(&parent_key_id), false, None, None)?,
        ));

        //w.close()?;
        res
    }

    pub fn retrieve_txs_with_proof_flag<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        refresh_from_node: bool,
        tx_id: Option<u32>,
        tx_slate_id: Option<Uuid>,
        pagination_start: Option<u32>,
        pagination_length: Option<u32>,
    ) -> Result<(bool, Vec<(TxLogEntry, bool)>), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let parent_key_id = w.parent_key_id();

        let mut validated = false;
        let mut output_list = None;
        if refresh_from_node {
            validated = update_outputs(&mut **w, false, None, None);

            // we need to check outputs for confirmations of ALL
            output_list = Some((
            validated,
            // OutputCommitMap Array to array of (OutputData, pedersen::Commitment)
            updater::retrieve_outputs(&mut **w,
                                      None,
                                      false,
                                      None,
                                      Some(&parent_key_id),
                                      None, None)?
                .iter().map(|ocm| (ocm.output.clone(), ocm.commit.clone())).collect()
            ));
        }

        let txs: Vec<TxLogEntry> =
            updater::retrieve_txs_with_outputs(&mut **w,
                                               None,
                                               tx_id,
                                               tx_slate_id,
                                               Some(&parent_key_id),
                                               false,
                                               pagination_start,
                                               pagination_length,
                                               output_list)?;
        let txs = txs
            .into_iter()
            .map(|t| {
                let tx_slate_id = t.tx_slate_id.clone();
                (
                    t,
                    tx_slate_id
                        .map(|i| TxProof::has_stored_tx_proof( w.get_data_file_dir(), &i.to_string()).unwrap_or(false))
                        .unwrap_or(false),
                )
            })
            .collect();

        let res = Ok((validated, txs));

        //w.close()?;
        res
    }

    struct TransactionInfo {
        tx_log: TxLogEntry,
        tx_commits: Vec<String>,  // pedersen::Commitment as strings
        validated: bool,
    }

    impl TransactionInfo {
        fn new(tx_log: TxLogEntry) -> Self {
            TransactionInfo {
                tx_log,
                tx_commits: Vec::new(),
                validated: false,
            }
        }
    }

    /// Validate transactions as bulk against full node kernels dump
    pub fn txs_bulk_validate<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        kernels_fn: &str, // file with kernels dump. One line per kernel
        result_fn: &str,  // Resulting file
    ) -> Result<(), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);

        let parent_key_id = w.parent_key_id();

        // Natural wallet's order should be good for us. Otherwise need to sort by tx_log.id
        let mut txs : Vec< TransactionInfo > = Vec::new();
        // Key: commit.  Value: index at txs
        let mut commit_to_tx: HashMap< String, usize > = HashMap::new();

        //
        for tx in w.tx_log_iter() {
            if tx.parent_key_id != parent_key_id {
                continue;
            }

            let mut tx_info = TransactionInfo::new(tx.clone());

            if let Some(uuid_str) = tx.tx_slate_id {
                if let Ok(transaction) = w.get_stored_tx_by_uuid(&uuid_str.to_string()) {
                    tx_info.tx_commits = transaction.body.kernels.iter().map(|k| grin_util::to_hex(k.excess.0.to_vec()) ).collect();
                };
            }

            if let Some(kernel) = tx.kernel_excess {
                tx_info.tx_commits.push( grin_util::to_hex(kernel.0.to_vec()) );
            }

            for commit in &tx_info.tx_commits {
                commit_to_tx.insert( commit.clone(), txs.len() );
            }

            txs.push(tx_info);
        };

        // Transactions are prepared. Now need to validate them.
        // Scanning node dump line by line and updating the valiated flag.
        // Normally there is a single kernel in tx. If any of kernels found - will make all transaction valid.

        let file = File::open(kernels_fn).map_err(|_| ErrorKind::FileNotFound(String::from(kernels_fn)))?;
        let reader = BufReader::new(file);

        // Read the file line by line using the lines() iterator from std::io::BufRead.
        for line in reader.lines() {
            let line = line.unwrap();

            if let Some(tx_idx) = commit_to_tx.get( &line ) {
                txs[*tx_idx].validated = true;
            }
        }

        // Done, now let's do a reporting
        let mut res_file = File::create(result_fn).map_err(|_| ErrorKind::FileUnableToCreate(String::from(result_fn)))?;

        write!(res_file, "id,uuid,type,address,create time,height,amount,fee,messages,node validation\n" )?;

        for t in &txs {
            let amount = if t.tx_log.amount_credited >= t.tx_log.amount_debited {
                grin_core::core::amount_to_hr_string(t.tx_log.amount_credited - t.tx_log.amount_debited, true)
            } else {
                format!("-{}", grin_core::core::amount_to_hr_string(t.tx_log.amount_debited - t.tx_log.amount_credited, true))
            };

            let report_str = format!("{},{},{},\"{}\",{},{},{},{},\"{}\",{}\n",
                                         t.tx_log.id,
                                         t.tx_log.tx_slate_id.map(|uuid| uuid.to_string()).unwrap_or("None".to_string()),
                                         match t.tx_log.tx_type { // TxLogEntryType print doesn't work for us
                                                TxLogEntryType::ConfirmedCoinbase => "Coinbase",
                                                TxLogEntryType::TxReceived => "Received",
                                                TxLogEntryType::TxSent => "Sent",
                                                TxLogEntryType::TxReceivedCancelled => "ReceivedCancelled",
                                                TxLogEntryType::TxSentCancelled => "SentCancelled",
                                         },
                                         t.tx_log.address.clone().unwrap_or("None".to_string()),
                                         t.tx_log.creation_ts.format("%Y-%m-%d %H:%M:%S"),
                                         t.tx_log.output_height,
                                         amount,
                                         t.tx_log.fee.map(|fee| grin_core::core::amount_to_hr_string(fee, true) ).unwrap_or("Unknown".to_string()),
                                         t.tx_log.messages.clone().map(|msg| {
                                             let msgs: Vec<String> = msg.messages.iter().filter_map(|m| m.message.clone()).collect();
                                             msgs.join(",").replace('"', "\"\"")
                                         }).unwrap_or(String::new()),
                                         if t.tx_commits.is_empty() {
                                             "Transaction data not complete"
                                         } else if t.validated {
                                             "true"
                                         } else {
                                             "false"
                                         }
            );
            write!(res_file, "{}", report_str )?;
        }

        Ok(())
    }

    pub fn retrieve_summary_info<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        refresh_from_node: bool,
        minimum_confirmations: u64,
    ) -> Result<(bool, WalletInfo), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let (tx, rx) = mpsc::channel();
        // Starting printing to console thread.
        let running = Arc::new( AtomicBool::new(true) );
        let updater = grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx, running.clone())?;
        let tx = Some(tx);

        let res = grin_wallet_libwallet::owner::retrieve_summary_info(wallet_inst,
                                                                None,
                                                                &tx,
                                                                refresh_from_node,
                                                                minimum_confirmations,
        )?;

        running.store(false, Ordering::Relaxed);
        let _ = updater.join();

        Ok(res)
    }

    pub fn initiate_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        active_account: Option<String>,
        address: Option<String>,
        amount: u64,
        minimum_confirmations: u64,
        max_outputs: u32,
        num_change_outputs: u32,
        selection_strategy_is_use_all: bool,
        message: Option<String>,
        outputs: Option<Vec<&str>>,  // outputs to include into the transaction
        version: Option<u16>, // Slate version
        routputs: usize,  // Number of resulting outputs. Normally it is 1
    ) -> Result<Slate, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);

        let params = grin_wallet_libwallet::InitTxArgs {
            src_acct_name: active_account,
            amount,
            minimum_confirmations,
            max_outputs,
            num_change_outputs,
            /// If `true`, attempt to use up as many outputs as
            /// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
            /// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
            /// minimizes fees. This will generally result in many inputs and a large change output(s),
            /// usually much larger than the amount being sent. If `false`, the transaction will include
            /// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
            /// value outputs.
            selection_strategy_is_use_all: selection_strategy_is_use_all,
            message,
            /// Optionally set the output target slate version (acceptable
            /// down to the minimum slate version compatible with the current. If `None` the slate
            /// is generated with the latest version.
            target_slate_version: version,
            /// Number of blocks from current after which TX should be ignored
            ttl_blocks: None,
            /// If set, require a payment proof for the particular recipient
            payment_proof_recipient_address: None,
            /// If true, just return an estimate of the resulting slate, containing fees and amounts
            /// locked without actually locking outputs or creating the transaction. Note if this is set to
            /// 'true', the amount field in the slate will contain the total amount locked, not the provided
            /// transaction amount
            address,
            estimate_only: None,
            /// Sender arguments. If present, the underlying function will also attempt to send the
            /// transaction to a destination and optionally finalize the result
            send_args: None,
        };

        let s = grin_wallet_libwallet::owner::init_send_tx( &mut **w,
                                                   None, params , false,
                                                            outputs, routputs)?;
        Ok(s)
    }

    // Lock put outputs and tx into the DB. Caller suppose to call it if slate was created and send sucessfully.
    pub fn tx_lock_outputs<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        slate: &Slate,
        address: Option<String>,
        participant_id: usize,
    ) -> Result<(), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        grin_wallet_libwallet::owner::tx_lock_outputs( &mut **w, None, slate, address, participant_id )?;
        Ok(())
    }

    pub fn finalize_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        slate: &mut Slate,
        tx_proof: Option<&mut TxProof>,
    ) -> Result<bool, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);

        let (slate_res, context) = grin_wallet_libwallet::owner::finalize_tx( &mut **w, None, slate )?;
        *slate = slate_res;

        if tx_proof.is_some() {
            let mut proof = tx_proof.unwrap();
            proof.amount = context.amount;
            proof.fee = context.fee;
            for input in context.input_commits {
                proof.inputs.push(input.clone());
            }
            for output in context.output_commits {
                proof.outputs.push(output.clone());
            }

            proof.store_tx_proof(w.get_data_file_dir(), &slate.id.to_string() )?;
        };

        Ok(true)
    }

    pub fn finalize_invoice_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        slate: &mut Slate,
    ) -> Result<bool, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        *slate = grin_wallet_libwallet::foreign::finalize_invoice_tx( &mut **w, None, slate )?;
        Ok(true)
    }

    pub fn cancel_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        tx_id: Option<u32>,
        tx_slate_id: Option<Uuid>,
    ) -> Result<(), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let (tx, rx) = mpsc::channel();
        // Starting printing to console thread.
        let running = Arc::new( AtomicBool::new(true) );
        let updater = grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx, running.clone())?;

        let tx = Some(tx);
        grin_wallet_libwallet::owner::cancel_tx( wallet_inst.clone(), None, &tx, tx_id, tx_slate_id )?;

        running.store(false, Ordering::Relaxed);
        let _ = updater.join();

        Ok(())
    }

    pub fn get_stored_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        uuid: &str
    ) -> Result<Transaction, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        Ok(w.get_stored_tx_by_uuid(uuid)?)
    }

    pub fn node_info<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    ) -> Result<NodeInfo, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);

        // first get height
        let mut height = 0;
        let mut total_difficulty = 0;
        match w.w2n_client().get_chain_tip() {
            Ok( (hght, _, total_diff) ) => {
                 height=hght;
                 total_difficulty=total_diff;
            },
            _ => (),
        }

        // peer info
        let mut peers : Vec<PeerInfoDisplay> = Vec::new();
        match w.w2n_client().get_connected_peer_info() {
            Ok(p) => peers = p,
            _ => (),
        };

        Ok(NodeInfo{height,total_difficulty,peers})
    }

    pub fn post_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        tx: &Transaction,
        fluff: bool
    ) -> Result<(), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let tx_hex = grin_util::to_hex(ser::ser_vec(tx,ser::ProtocolVersion(1) ).unwrap());
        let client = {
            wallet_lock!(wallet_inst, w);
            w.w2n_client().clone()
        };
        client.post_tx(&TxWrapper { tx_hex: tx_hex }, fluff)?;
        Ok(())
    }

    pub fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
        slate.verify_messages()?;
        Ok(())
    }


    // restore is a repairs. Since nothing exist, it will do what is needed.
    pub fn restore<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>
    ) -> Result<(), Error>
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        check_repair(wallet_inst, 1, true)
    }

    pub fn check_repair<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        start_height: u64,
        delete_unconfirmed: bool
    ) -> Result<(), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let (tx, rx) = mpsc::channel();
        // Starting printing to console thread.
        let running = Arc::new( AtomicBool::new(true) );
        let updater = grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx, running.clone())?;

        let tx = Some(tx);
        grin_wallet_libwallet::owner::scan( wallet_inst.clone(),
                      None,
                      Some(start_height),
                       delete_unconfirmed,
                      &tx,
                      None,
        )?;

        running.store(false, Ordering::Relaxed);
        let _ = updater.join();

        Ok(())
    }

    pub fn dump_wallet_data<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        file_name: Option<String>,
    ) -> Result<(), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {

        // Starting printing to console thread.
        let running = Arc::new( AtomicBool::new(true) );
        let (tx, rx) = mpsc::channel();
        let updater = grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx, running.clone())?;

        grin_wallet_libwallet::owner::dump_wallet_data(
            wallet_inst,
            &tx,
            file_name,
        )?;

        running.store(false, Ordering::Relaxed);
        let _ = updater.join();

        Ok(())
    }


    pub fn sync<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        update_all: bool,
        print_progress: bool,
    ) -> Result<bool, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let mut status_send_channel: Option<Sender<StatusMessage>> = None;

        let running = Arc::new( AtomicBool::new(true) );
        let mut updater : Option<JoinHandle<()>> = None;

        if print_progress {
            let (tx, rx) = mpsc::channel();
            // Starting printing to console thread.
            updater = Some(grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx, running.clone())?);
            status_send_channel = Some(tx);
        }

        let res = grin_wallet_libwallet::owner::update_wallet_state(
            wallet_inst,
            None,
            &status_send_channel,
            update_all,
            None, // Need Update for all accounts
        )?;

        running.store(false, Ordering::Relaxed);
        if updater.is_some() {
            let _ = updater.unwrap().join();
        }

        Ok(res)
    }

    pub fn scan_outputs<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        pub_keys: Vec<PublicKey>,
        output_fn : String
    )  -> Result<(), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        update_outputs(&mut **w, true, None, None);
        crate::wallet::api::restore::scan_outputs(&mut **w, pub_keys, output_fn)?;
        Ok(())
    }

    pub fn node_height<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    ) -> Result<(u64, bool), Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        let res = {
            wallet_lock!(wallet_inst, w);
            w.w2n_client().get_chain_tip()
        };
        match res {
            Ok(height) => Ok((height.0, true)),
            Err(_) => {
                let outputs = retrieve_outputs(wallet_inst.clone(), true, false, None, None, None)?;
                let height = match outputs.1.iter().map(|ocm| ocm.output.height).max() {
                    Some(height) => height,
                    None => 0,
                };
                Ok((height, false))
            }
        }
    }

    fn update_outputs<'a, T: ?Sized, C, K>(wallet: &mut T, update_all: bool, height: Option<u64>, accumulator: Option<Vec<grin_api::Output>>) -> bool
        where
            T: WalletBackend<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        // Updating outptus for all accounts
        match updater::refresh_outputs(wallet, None, None, update_all, height, accumulator) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn get_stored_tx_proof<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        id: u32) -> Result<TxProof, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let parent_key_id = w.parent_key_id();
        let txs: Vec<TxLogEntry> =
            updater::retrieve_txs(&mut **w, None,Some(id), None, Some(&parent_key_id), false, None, None)?;
        if txs.len() != 1 {
            return Err(ErrorKind::TransactionHasNoProof)?;
        }
        let uuid = txs[0]
            .tx_slate_id
            .ok_or_else(|| ErrorKind::TransactionHasNoProof)?;
        TxProof::get_stored_tx_proof( w.get_data_file_dir(), &uuid.to_string())
    }

    pub fn verify_tx_proof(
        tx_proof: &TxProof,
    ) -> Result<
        (
            Option<GrinboxAddress>,
            GrinboxAddress,
            u64,
            Vec<pedersen::Commitment>,
            pedersen::Commitment,
        ),
        Error,
    > {
        let secp = &Secp256k1::with_caps(ContextFlag::Commit);

        let (destination, slate) = tx_proof
            .verify_extract(None)
            .map_err(|_| ErrorKind::VerifyProof)?;

        let inputs_ex = tx_proof.inputs.iter().collect::<HashSet<_>>();

        let mut inputs: Vec<pedersen::Commitment> = slate
            .tx
            .inputs()
            .iter()
            .map(|i| i.commitment())
            .filter(|c| !inputs_ex.contains(c))
            .collect();

        let outputs_ex = tx_proof.outputs.iter().collect::<HashSet<_>>();

        let outputs: Vec<pedersen::Commitment> = slate
            .tx
            .outputs()
            .iter()
            .map(|o| o.commitment())
            .filter(|c| !outputs_ex.contains(c))
            .collect();

        let excess = &slate.participant_data[1].public_blind_excess;

        let excess_parts: Vec<&PublicKey> = slate
            .participant_data
            .iter()
            .map(|p| &p.public_blind_excess)
            .collect();
        let excess_sum =
            PublicKey::from_combination(secp, excess_parts).map_err(|_| ErrorKind::VerifyProof)?;

        let commit_amount = secp.commit_value(tx_proof.amount)?;
        inputs.push(commit_amount);

        let commit_excess = secp.commit_sum(outputs.clone(), inputs)?;
        let pubkey_excess = commit_excess.to_pubkey(secp)?;

        if excess != &pubkey_excess {
            return Err(ErrorKind::VerifyProof.into());
        }

        let mut input_com: Vec<pedersen::Commitment> =
            slate.tx.inputs().iter().map(|i| i.commitment()).collect();

        let mut output_com: Vec<pedersen::Commitment> =
            slate.tx.outputs().iter().map(|o| o.commitment()).collect();

        input_com.push(secp.commit(0, slate.tx.offset.secret_key(secp)?)?);

        output_com.push(secp.commit_value(slate.fee)?);

        let excess_sum_com = secp.commit_sum(output_com, input_com)?;

        if excess_sum_com.to_pubkey(secp)? != excess_sum {
            return Err(ErrorKind::VerifyProof.into());
        }

        return Ok((
            destination,
            tx_proof.address.clone(),
            tx_proof.amount,
            outputs,
            excess_sum_com,
        ));
    }

    pub fn derive_address_key<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        index: u32
    ) -> Result<SecretKey, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let keychain = w.keychain(None)?;
        hasher::derive_address_key(&keychain, index).map_err(|e| e.into())
    }

    pub fn initiate_receive_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        address: Option<String>,
        active_account: Option<String>,
        amount: u64,
        num_outputs: usize,
        message: Option<String>,
    ) -> Result< Slate, Error >
    where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);

        let params = grin_wallet_libwallet::IssueInvoiceTxArgs {
            dest_acct_name: active_account,
            amount,
            message,
            /// Optionally set the output target slate version (acceptable
            /// down to the minimum slate version compatible with the current. If `None` the slate
            /// is generated with the latest version.
            target_slate_version: None,
            address,
        };

        let s = grin_wallet_libwallet::owner::issue_invoice_tx(&mut **w,
                          None, params , false, num_outputs)?;
        Ok(s)
    }

    pub fn build_coinbase<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        block_fees: &BlockFees
    ) -> Result<CbData, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);
        let res = updater::build_coinbase(&mut **w, None, block_fees, false )?;
        Ok(res)
    }

    pub fn receive_tx<'a, L, C, K>(
        wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
        address: Option<String>,
        slate: &mut Slate,
        message: Option<String>,
        key_id: Option<&str>,
        output_amounts: Option<Vec<u64>>,
        dest_acct_name: Option<&str>,
    ) -> Result<Slate, Error>
        where
            L: WalletLCProvider<'a, C, K>,
            C: NodeClient + 'a,
            K: Keychain + 'a,
    {
        wallet_lock!(wallet_inst, w);

        let s = grin_wallet_libwallet::foreign::receive_tx(
            &mut **w,
            None,
            slate,
            address,
            key_id,
            output_amounts,
            dest_acct_name,
            message,
            false,
        )?;
        Ok(s)
    }
