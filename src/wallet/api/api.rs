use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

use grin_p2p::types::PeerAddr;
pub use grin_util::secp::{Message};
use grin_core::core::hash::{Hash};
use grin_util::secp::{ContextFlag, Secp256k1, Signature};
use grin_p2p::types::PeerInfoDisplay;


use grin_p2p::types::PeerInfoDisplayLegacy;
use grin_wallet_libwallet::proof::crypto::Hex;
use grin_wallet_libwallet::proof::tx_proof::TxProof;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use grin_wallet_libwallet::{AcctPathMapping, NodeClient, Slate, TxLogEntry,
                            WalletInfo, OutputCommitMapping, WalletInst, WalletLCProvider,
                            StatusMessage, TxLogEntryType, OutputData};
use grin_wallet_libwallet::api_impl::types::SwapStartArgs;
use grin_core::core::Transaction;
use grin_keychain::{Identifier};
use grin_wallet_impls::keychain::Keychain;
use grin_util::secp::key::{ PublicKey, SecretKey};
use crate::common::{Arc, Mutex, Error, ErrorKind};

use grin_keychain::{SwitchCommitmentType, ExtKeychainPath};
use grin_wallet_libwallet::internal::{updater,keys};
use std::sync::mpsc;
use grin_wallet_libwallet::proof::hasher;
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
            let signature = keychain.sign(&msg_message,0, &id, SwitchCommitmentType::None)?;

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
    let pk = grin_util::from_hex(pubkey)?;
    let pk = PublicKey::from_slice(&secp, &pk)?;

    let signature = grin_util::from_hex(signature)?;
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
    let sec_key = keychain.derive_key(amount, &id, SwitchCommitmentType::Regular)?;
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

pub fn get_current_account<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>
) -> Result<AcctPathMapping, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    let account = accounts(wallet_inst.clone())?;
    wallet_lock!(wallet_inst, w);
    let cur_acc_path = w.parent_key_id();

    for a in account {
        if a.path == cur_acc_path {
            return Ok(a);
        }
    }

    Err( ErrorKind::GenericError(format!("Not found account name for path {:?}", cur_acc_path)).into() )
}

// Set current account by path
pub fn set_current_account<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    name: &str,
) -> Result<(), Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    wallet_lock!(wallet_inst, w);
    w.set_parent_key_id_by_name(name)?;
    Ok(())
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
    tx: Option<&TxLogEntry>,
    pagination_start: Option<u32>,
    pagination_len:   Option<u32>,
) -> Result<(bool, Vec<OutputCommitMapping>), Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    let mut validated = false;
    if refresh_from_node {
        validated = sync(
            wallet_inst.clone(),
            true,
        )?;
    }

    wallet_lock!(wallet_inst, w);
    let parent_key_id = w.parent_key_id();

    let res = Ok((
        validated,
        updater::retrieve_outputs(&mut **w,
                                  None,
                                  include_spent,
                                  tx,
                                  &parent_key_id,
                                  pagination_start,
                                  pagination_len)?,
    ));

    res
}

pub fn _retrieve_txs<'a, L, C, K>(
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
        validated = sync( wallet_inst.clone(), true )?;
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
    let mut validated = false;
    if refresh_from_node {
        validated = sync( wallet_inst.clone(), true )?;
    }

    wallet_lock!(wallet_inst, w);
    let parent_key_id = w.parent_key_id();

    let txs: Vec<TxLogEntry> =
        updater::retrieve_txs(&mut **w,
                              None,
                              tx_id,
                              tx_slate_id,
                              Some(&parent_key_id),
                              false,
                              pagination_start,
                              pagination_length)?;

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

    res
}

struct TransactionInfo {
    tx_log: TxLogEntry,
    tx_kernels: Vec<String>,  // pedersen::Commitment as strings.  tx kernel, that can be used to validate send transactions
    tx_outputs: Vec<OutputData>, // Output data from transaction.
    validated: bool,
    validation_flags: String,
    warnings: Vec<String>,
}

impl TransactionInfo {
    fn new(tx_log: TxLogEntry) -> Self {
        TransactionInfo {
            tx_log,
            tx_kernels: Vec::new(),
            tx_outputs: Vec::new(),
            validated: false,
            validation_flags: String::new(),
            warnings: Vec::new(),
        }
    }
}

fn calc_best_merge(
    outputs : &mut VecDeque<OutputData>,
    transactions: &mut VecDeque<TxLogEntry>,
) -> (Vec<(TxLogEntry, Vec<OutputData>, bool)>, // Tx to output mapping
      Vec<OutputData>) // Outstanding outputs
{
    let mut res : Vec<(TxLogEntry,Vec<OutputData>, bool)> = Vec::new();

    let mut next_canlelled = true;

    while let Some(tx) = transactions.pop_front() {
        if outputs.is_empty() { // failed to find the outputs
            res.push( (tx.clone(), vec![], false) );
            continue;
        }

        if tx.num_outputs==0 {
            res.push( (tx.clone(), vec![], true) );
            continue;
        }

        if tx.is_cancelled() {
            if res.is_empty() { // first is cancelled. Edge case. Let's get transaction is possible
                next_canlelled = tx.amount_credited != outputs.front().unwrap().value;
            }

            if next_canlelled {
                // normally output is deleted form the DB. But there might be exceptions.
                res.push((tx.clone(), vec![], true));
                continue;
            }
        }


        assert!(tx.num_outputs>0);

        // Don't do much. Just chck the current ones.
        if tx.num_outputs <= outputs.len() {
            let mut found = false;

            for i in 0..(outputs.len()-(tx.num_outputs-1)) {
                let mut amount: u64 = 0;
                for k in 0..tx.num_outputs {
                    amount += outputs[k+i].value;
                }

                if amount == tx.amount_credited {
                    let mut res_outs: Vec<OutputData> = Vec::new();
                    for _ in 0..tx.num_outputs {
                        res_outs.push( outputs.remove(i).unwrap() );
                    }
                    found = true;

                    if let Some(o2) = outputs.get(i) {
                        next_canlelled = o2.n_child - res_outs.last().unwrap().n_child > 1; // normally it is 1
                    }
                    else {
                        next_canlelled = true;
                    }

                    res.push((tx.clone(), res_outs, true));
                    break;
                }
            }
            if !found {
                res.push( (tx.clone(), vec![], false) );
            }
        }
    }

    ( res, outputs.iter().map(|o| o.clone()).collect::<Vec<OutputData>>() )
}

/// Validate transactions as bulk against full node kernels dump
pub fn txs_bulk_validate<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    kernels_fn: &str, // file with kernels dump. One line per kernel
    outputs_fn: &str, // file with outputs dump. One line per output
    result_fn: &str,  // Resulting file
) -> Result<(), Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    wallet_lock!(wallet_inst, w);

    let parent_key_id = w.parent_key_id();

    // Validation will be processed for all transactions...

    // Natural wallet's order should be good for us. Otherwise need to sort by tx_log.id
    let mut txs : Vec<TransactionInfo> = Vec::new();
    // Key: commit.  Value: index at txs
    let mut kernel_to_tx: HashMap< String, usize > = HashMap::new();
    let mut output_to_tx: HashMap< String, usize > = HashMap::new();
    let mut tx_id_to_tx: HashMap< u32, usize > = HashMap::new();

    // Scanning both transactions and outputs. Doing that for all accounts. Filtering will be later
    // Outputs don't have to start from the n_child  and they don't have to go in the order because of possible race condition at recovery steps
    let mut wallet_outputs : VecDeque<OutputData> = w.iter()
        .filter(|o| o.root_key_id == parent_key_id && o.commit.is_some() )
        .collect();

    let mut wallet_transactions: VecDeque<TxLogEntry> = w.tx_log_iter()
        .filter(|t| t.parent_key_id == parent_key_id )
        .collect();

    let wallet_outputs_len = wallet_outputs.len();

    let (
        tx_to_output,
        outstanding_outputs,
    ) = calc_best_merge( &mut wallet_outputs, &mut wallet_transactions );

    for ( tx, outputs, success ) in tx_to_output {
        let mut tx_info = TransactionInfo::new(tx.clone());

        tx_info.tx_outputs = outputs;

        if !success {
            tx_info.warnings.push("Failed to descover outputs".to_string());
        }

        if tx.tx_type == TxLogEntryType::ConfirmedCoinbase || tx.tx_type == TxLogEntryType::TxReceived {
            if tx_info.tx_log.num_outputs == 0 {
                tx_info.warnings.push("Tx Has no outputs".to_string());
                println!("WARNING: Receive transaction id {} doesn't have any outputs. Please check why it is happaning. {:?}", tx.id, tx);
            }
        }

        ///////////////////////////////////////////////////////////
        // Taking case about Send type of transactions. Sends are expected to have slate with a kernel
        // Note, output with change is a secondary source of verification because of cut through.

        if tx.tx_type == TxLogEntryType::TxSent {
            if tx.tx_slate_id.is_none() && tx.kernel_excess.is_none() {
                tx_info.warnings.push("Transaction doesn't have UUID".to_string());
                println!("WARNING: Sent transaction id {} doesn't have uuid or kernel data", tx.id );
            }
        }

        if tx.tx_type != TxLogEntryType::TxReceived && tx.tx_type != TxLogEntryType::TxReceivedCancelled {
            if let Some(uuid_str) = tx.tx_slate_id {
                if let Ok(transaction) = w.get_stored_tx_by_uuid(&uuid_str.to_string()) {
                    tx_info.tx_kernels = transaction.body.kernels.iter().map(|k| grin_util::to_hex(k.excess.0.to_vec())).collect();
                } else {
                    if tx.tx_type == TxLogEntryType::TxSent {
                        tx_info.warnings.push("Transaction slate not found".to_string());
                        println!("INFO: Not found slate data for id {} and uuid {}. Might be recoverable issue", tx.id, uuid_str);
                    }
                }
            }
            if let Some(kernel) = tx.kernel_excess {
                tx_info.tx_kernels.push(grin_util::to_hex(kernel.0.to_vec()));
            }
        }

        if tx.tx_type == TxLogEntryType::TxSent {
            if tx_info.tx_kernels.is_empty() {
                tx_info.warnings.push("No Kernels found".to_string());
                if tx_info.tx_outputs.is_empty() {
                    println!("WARNING: For send transaction id {} we not found any kernels and no change outputs was found. We will not be able to validate it.", tx.id );
                }
                else {
                    println!("WARNING: For send transaction id {} we not found any kernels, but {} outputs exist. Outputs might not exist because of cut though.", tx.id, tx_info.tx_outputs.len() );
                }
            }
        }

        // Data is ready, let's collect it
        let tx_idx = txs.len();
        for kernel in &tx_info.tx_kernels {
            kernel_to_tx.insert(kernel.clone(), tx_idx);
        }

        for out in &tx_info.tx_outputs {
            if let Some(commit) = &out.commit {
                output_to_tx.insert(commit.clone(), tx_idx);
            }
            else {
                tx_info.warnings.push("Has Output without commit record".to_string());
                println!("WARNING: Transaction id {} has broken Output without commit record. It can't be used for validation. This Transaction has outpts number: {}. Output data: {:?}", tx.id, tx_info.tx_outputs.len(), out);
            }
        }

        tx_id_to_tx.insert( tx.id, tx_idx );

        txs.push(tx_info);
    }

    // Transactions are prepared. Now need to validate them.
    // Scanning node dump line by line and updating the valiated flag.


    // ------------ Send processing first because sends are end points for Recieved Outputs. ---------------------
    // If receive outputs is not in the chain but end point send was delivered - mean that it was a cut through and transaction is valid
    // Normally there is a single kernel in tx. If any of kernels found - will make all transaction valid.
    {
        let file = File::open(kernels_fn).map_err(|e| ErrorKind::FileNotFound(kernels_fn.to_string(), format!("{}",e)))?;
        let reader = BufReader::new(file);

        // Read the file line by line using the lines() iterator from std::io::BufRead.
        for line in reader.lines() {
            let line = line.unwrap();

            if let Some(tx_idx) = kernel_to_tx.get(&line) {
                txs[*tx_idx].validated = true;
                txs[*tx_idx].validation_flags += "K";
            }
        }

    }

    // ---------- Processing Outputs. Targeting 'receive' and partly 'send' -----------------
    {
        {
            let file = File::open(outputs_fn).map_err(|e| ErrorKind::FileNotFound(outputs_fn.to_string(), format!("{}",e)))?;
            let reader = BufReader::new(file);

            // Read the file line by line using the lines() iterator from std::io::BufRead.
            for output in reader.lines() {
                let output = output.unwrap();

                if let Some(tx_idx) = output_to_tx.get(&output) {
                    txs[*tx_idx].validated = true;
                    txs[*tx_idx].validation_flags += "O";
                }
            }
        }
    }

    // Processing outputs by Send target - it is a Cut through Case.
    // Do that for Recieve transactions without confirmations
    {
        for i in 0..txs.len() {
            let t = &txs[i];

            if t.validated {
                continue;
            }

            let mut validated = false;

            for out in &t.tx_outputs {
                if let Some(tx_log_entry) = out.tx_log_entry {
                    if let Some(tx_idx) = tx_id_to_tx.get(&tx_log_entry) {
                        let tx_info = &txs[*tx_idx];
                        if (tx_info.tx_log.tx_type == TxLogEntryType::TxSent || tx_info.tx_log.tx_type == TxLogEntryType::TxSentCancelled)
                            && tx_info.validated {
                            // We can validate this transaction because output was spent sucessfully
                            validated = true;
                        }
                    }
                }
            }

            drop(t);

            if validated {
                txs[i].validated = true;
                txs[i].validation_flags += "S";
            }
        }
    }

    // Done, now let's do a reporting
    let mut res_file = File::create(result_fn).map_err(|e| ErrorKind::FileUnableToCreate(result_fn.to_string(), format!("{}",e)))?;

    write!(res_file, "id,uuid,type,address,create time,height,amount,fee,messages,node validation,validation flags,validation warnings\n" )?;

    for t in &txs {
        let amount = if t.tx_log.amount_credited >= t.tx_log.amount_debited {
            grin_core::core::amount_to_hr_string(t.tx_log.amount_credited - t.tx_log.amount_debited, true)
        } else {
            format!("-{}", grin_core::core::amount_to_hr_string(t.tx_log.amount_debited - t.tx_log.amount_credited, true))
        };

        let report_str = format!("{},{},{},\"{}\",{},{},{},{},\"{}\",{},{},\"{}\"\n",
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
                                 if t.validated {
                                     "true"
                                 } else {
                                     "false"
                                 },
                                 t.validation_flags,
                                 t.warnings.join("; "),
        );
        write!(res_file, "{}", report_str )?;
    }

    if !outstanding_outputs.is_empty() {



        println!("WARNING: There are {} from {} outstanding outputs that wasn't used. That affect accuracy of results!!!", outstanding_outputs.len(), wallet_outputs_len );
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
    status_send_channel: &Option<Sender<StatusMessage>>,
    ttl_blocks: u64,
    do_proof: bool,
) -> Result<Slate, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    // Caller is responsible for refresh call
    grin_wallet_libwallet::owner::update_wallet_state(wallet_inst.clone(), None, status_send_channel )?;

    wallet_lock!(wallet_inst, w);

    let ttl_blocks = if ttl_blocks == 0 { None } else { Some(ttl_blocks) };
    //for tor sending, address can also be used as payment proof address
    let mut proof_address = None;
    if do_proof {
        if let Some(addr) = address.clone() {
            debug!("the address in init_tx is: {}", &addr);
            //if it is an onion address, need to remove the http:// or https:// and .onion.
            let mut addr_change = addr;
            if addr_change.starts_with("HTTP://") || addr_change.starts_with("HTTPS://") {
                addr_change = addr_change.replace("HTTP://", "");
                addr_change = addr_change.replace("HTTPS://", "");
            }
            if addr_change.starts_with("http://") || addr_change.starts_with("http://") {
                addr_change = addr_change.replace("http://", "");
                addr_change = addr_change.replace("https://", "");
            }
            if addr_change.ends_with(".ONION") {
                addr_change = addr_change.replace(".ONION", "");
            }
            if addr_change.ends_with(".onion") {
                addr_change = addr_change.replace(".onion", "");
            }
            if addr_change.ends_with(".ONION/") {
                addr_change = addr_change.replace(".ONION/", "");
            }
            if addr_change.ends_with(".onion/") {
                addr_change = addr_change.replace(".onion/", "");
            }
            if addr_change.len() == 56 {
                let proof_addr = ProvableAddress::from_str(&addr_change)?;
                proof_address = Some(proof_addr);
            }
        }
    }

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
        ttl_blocks: ttl_blocks,
        /// If set, require a payment proof for the particular recipient
        payment_proof_recipient_address: proof_address,
        /// If true, just return an estimate of the resulting slate, containing fees and amounts
        /// locked without actually locking outputs or creating the transaction. Note if this is set to
        /// 'true', the amount field in the slate will contain the total amount locked, not the provided
        /// transaction amount
        address,
        estimate_only: None,
        /// Sender arguments. If present, the underlying function will also attempt to send the
        /// transaction to a destination and optionally finalize the result
        /// Whether or not to exclude change outputs, not needed in mwc713.
        exclude_change_outputs: Some(false),
        /// Number of confirmations for change outputs, default fine, not used in mwc713.
        minimum_confirmations_change_outputs: 1,
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
    slate: &mut Slate
) -> Result<(), Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    wallet_lock!(wallet_inst, w);

    let (slate_res, _context) = grin_wallet_libwallet::owner::finalize_tx( &mut **w, None, slate, true )?;
    *slate = slate_res;

    Ok(())
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
    let mut peers : Vec<PeerInfoDisplayLegacy> = Vec::new();
    match w.w2n_client().get_connected_peer_info() {
        Ok(p) => { peers = p; },
        _ => { 
		match w.w2n_client().get_connected_peer_info() {
			Ok(p2) => { peers = p2; },
			_ => (),
		}
		() },
    };

    let mut peers_ret: Vec<PeerInfoDisplay> = Vec::new();

    for peer in peers {
        let peer_display = PeerInfoDisplay {
		capabilities: peer.capabilities,
		user_agent: peer.user_agent,
		version: peer.version,
		addr: PeerAddr::from_str(&peer.addr),
		direction: peer.direction,
		total_difficulty: peer.total_difficulty,
		height: peer.height,
	};
	peers_ret.push(peer_display);
    }

    Ok(NodeInfo{height,total_difficulty,peers:peers_ret})
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
    let client = {
        wallet_lock!(wallet_inst, w);
        w.w2n_client().clone()
    };
    client.post_tx(tx, fluff)?;
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
                                        true,
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
        &status_send_channel
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
        .map_err(|_| ErrorKind::TxStoredProof.into())
}

// pub fn verify_tx_proof(
//     tx_proof: &TxProof,
// ) -> Result<
//     (
//         Option<ProvableAddress>,
//         ProvableAddress,
//         u64,
//         Vec<pedersen::Commitment>,
//         pedersen::Commitment,
//     ),
//     Error,
// > {
//     let secp = &Secp256k1::with_caps(ContextFlag::Commit);
//
//     let (destination, slate) = tx_proof
//         .verify_extract(None)
//         .map_err(|e| ErrorKind::VerifyProof(format!("{}",e)))?;
//
//     let inputs_ex = tx_proof.inputs.iter().collect::<HashSet<_>>();
//
//     let mut inputs: Vec<pedersen::Commitment> = slate
//         .tx
//         .inputs()
//         .iter()
//         .map(|i| i.commitment())
//         .filter(|c| !inputs_ex.contains(c))
//         .collect();
//
//     let outputs_ex = tx_proof.outputs.iter().collect::<HashSet<_>>();
//
//     let outputs: Vec<pedersen::Commitment> = slate
//         .tx
//         .outputs()
//         .iter()
//         .map(|o| o.commitment())
//         .filter(|c| !outputs_ex.contains(c))
//         .collect();
//
//     let excess = &slate.participant_data[1].public_blind_excess;
//
//     let excess_parts: Vec<&PublicKey> = slate
//         .participant_data
//         .iter()
//         .map(|p| &p.public_blind_excess)
//         .collect();
//     let excess_sum =
//         PublicKey::from_combination(secp, excess_parts).map_err(|e| ErrorKind::VerifyProof(format!("Unable to combile public keys, {}", e)) )?;
//
//     let commit_amount = secp.commit_value(tx_proof.amount)?;
//     inputs.push(commit_amount);
//
//     let commit_excess = secp.commit_sum(outputs.clone(), inputs)?;
//     let pubkey_excess = commit_excess.to_pubkey(secp)?;
//
//     if excess != &pubkey_excess {
//         return Err(ErrorKind::VerifyProof("Excess pub keys mismatch".to_string()).into());
//     }
//
//     let mut input_com: Vec<pedersen::Commitment> =
//         slate.tx.inputs().iter().map(|i| i.commitment()).collect();
//
//     let mut output_com: Vec<pedersen::Commitment> =
//         slate.tx.outputs().iter().map(|o| o.commitment()).collect();
//
//     input_com.push(secp.commit(0, slate.tx.offset.secret_key(secp)?)?);
//
//     output_com.push(secp.commit_value(slate.fee)?);
//
//     let excess_sum_com = secp.commit_sum(output_com, input_com)?;
//
//     if excess_sum_com.to_pubkey(secp)? != excess_sum {
//         return Err(ErrorKind::VerifyProof("Excess sum mismatch".to_string()).into());
//     }
//
//     return Ok((
//         Some(destination),
//         tx_proof.address.clone(),
//         tx_proof.amount,
//         outputs,
//         excess_sum_com,
//     ));
// }

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
        true,
        0,
    )?;
    Ok(s)
}

pub fn swap_create_from_offer<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    filename: String,
)-> Result<String, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    let swap_id = grin_wallet_libwallet::owner_swap::swap_create_from_offer(wallet_inst, None, filename)?;
    Ok(swap_id)
}

pub fn swap_start<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    mwc_amount: u64,
    secondary_currency: String,
    secondary_amount: String,
    secondary_redeem_address: String,
    seller_lock_first: bool,
    minimum_confirmations: Option<u64>,
    mwc_confirmations: u64,
    secondary_confirmations: u64,
    message_exchange_time_sec: u64,
    redeem_time_sec: u64,
    buyer_communication_method: String,
    buyer_communication_address: String,
)-> Result<String, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    let params = SwapStartArgs {
        mwc_amount,
        secondary_currency,
        secondary_amount,
        secondary_redeem_address,
        seller_lock_first,
        minimum_confirmations,
        mwc_confirmations,
        secondary_confirmations,
        message_exchange_time_sec,
        redeem_time_sec,
        buyer_communication_method,
        buyer_communication_address,
    };

    let swap_id = grin_wallet_libwallet::owner_swap::swap_start(wallet_inst, None, &params)?;
    Ok(swap_id)
}
