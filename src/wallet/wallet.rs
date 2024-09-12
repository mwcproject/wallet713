use common::config::Wallet713Config;
use common::Error;
use uuid::Uuid;

use crate::common::{Arc, Mutex};
use grin_core::core::Transaction;
use grin_keychain::keychain::ExtKeychain;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_wallet_impls::lifecycle::WalletSeed;
use grin_wallet_impls::node_clients::HTTPNodeClient;
use grin_wallet_libwallet::{
    AcctPathMapping, NodeClient, OutputCommitMapping, ScannedBlockInfo, Slate, SlatePurpose,
    StatusMessage, TxLogEntry, WalletInst,
};

use crate::wallet::api::api;
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
use grin_util::ZeroingString;
use grin_wallet_controller::display;
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use grin_wallet_libwallet::api_impl::owner_updater;
use grin_wallet_libwallet::proof::proofaddress;
use grin_wallet_libwallet::proof::proofaddress::{ProofAddressType, ProvableAddress};
use grin_wallet_libwallet::proof::tx_proof::TxProof;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use grin_util::secp::{ContextFlag, Secp256k1};

pub struct Wallet {
    backend: Option<
        Arc<
            Mutex<
                Box<
                    dyn WalletInst<
                        'static,
                        DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
                        HTTPNodeClient,
                        ExtKeychain,
                    >,
                >,
            >,
        >,
    >,

    // Updater comes from mwc-wallet. The only purpose is update statused in the background...
    /// Stop state for update thread
    pub updater_running: Arc<AtomicBool>,
    /// Update thread
    updater_handler: Option<JoinHandle<()>>,
}

impl Wallet {
    pub fn new() -> Self {
        Self {
            backend: None,
            updater_running: Arc::new(AtomicBool::new(false)),
            updater_handler: None,
        }
    }

    pub fn seed_exists(config: &Wallet713Config) -> bool {
        match config.get_data_path_str() {
            Ok(path) => WalletSeed::seed_file_exists(&path).unwrap_or(false),
            _ => false,
        }
    }

    pub fn unlock(
        &mut self,
        config: &Wallet713Config,
        account: &str,
        passphrase: grin_util::ZeroingString,
    ) -> Result<(), Error> {
        if self.backend.is_some() {
            return Err(Error::WalletAlreadyUnlocked);
        }

        self.create_wallet_instance(config, account, passphrase)
            .map_err(|e| {
                warn!("Unable to unlock wallet, {}", e);
                Error::WalletUnlockFailed
            })?;
        Ok(())
    }

    pub fn getrootpublickey(&mut self, message: Option<&str>) -> Result<(), Error> {
        api::show_rootpublickey(self.get_wallet_instance()?, message).map_err(|err| {
            Error::GenericError(format!("Unable to get a public key, {}", err))
        })?;
        Ok(())
    }

    pub fn verifysignature(
        &mut self,
        message: &str,
        signature: &str,
        pubkey: &str,
    ) -> Result<(), Error> {
        api::verifysignature(message, signature, pubkey).map_err(|err| {
            Error::GenericError(format!("Unable to verify signature, {}", err))
        })?;
        Ok(())
    }

    pub fn scan_outputs(
        &mut self,
        pub_keys: Vec<PublicKey>,
        output_fn: String,
    ) -> Result<(), Error> {
        api::scan_outputs(self.get_wallet_instance()?, pub_keys, output_fn)?;
        Ok(())
    }

    pub fn getnextkey(&mut self, amount: u64) -> Result<(), Error> {
        let key = api::getnextkey(self.get_wallet_instance()?, amount)?;
        println!("{:?}", key);
        Ok(())
    }

    pub fn node_info(&mut self) -> Result<(), Error> {
        // Add retry for the node info.
        let ni = match api::node_info(self.get_wallet_instance()?) {
            Ok(ni) => ni,
            Err(_) => api::node_info(self.get_wallet_instance()?)?,
        };

        // this is an error condition
        if ni.height == 0 && ni.total_difficulty == 0 {
            cli_message!("Error: Error occured trying to contact node!");
        } else {
            // otherwise it worked, print it out here.
            cli_message!("Node Info:");
            cli_message!("Height: {}", ni.height);
            cli_message!("Total_Difficulty: {}", ni.total_difficulty);
            cli_message!("PeerInfo: {:?}", ni.peers);
        }
        Ok(())
    }

    pub fn account_path(
        &mut self,
        account: &str,
    ) -> Result<Option<grin_wallet_libwallet::AcctPathMapping>, Error> {
        let acct_mappings = api::accounts(self.get_wallet_instance()?)?;
        for m in acct_mappings {
            if m.label == account {
                return Ok(Some(m.clone()));
            }
        }
        Ok(None)
    }

    pub fn show_mnemonic(
        &self,
        config: &Wallet713Config,
        passphrase: ZeroingString,
    ) -> Result<(), Error> {
        let seed = WalletSeed::from_file(&config.get_data_path_str()?, passphrase)?;
        grin_wallet_impls::lifecycle::show_recovery_phrase(ZeroingString::from(
            seed.to_mnemonic()?,
        ));
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.backend.is_none()
    }

    pub fn complete(
        &mut self,
        seed: WalletSeed,
        config: &Wallet713Config,
        account: &str,
        passphrase: grin_util::ZeroingString,
        create_new: bool,
        short_seed: bool
    ) -> Result<WalletSeed, Error> {
        let seed = self.init_seed(&config, passphrase.clone(), create_new, true, Some(seed), short_seed)?;
        //self.init_backend(&wallet_config, &config, passphrase)?;
        self.unlock(config, account, passphrase)?;
        Ok(seed)
    }

    pub fn init(
        &mut self,
        config: &Wallet713Config,
        passphrase: grin_util::ZeroingString,
        create_new: bool,
        short_seed: bool
    ) -> Result<WalletSeed, Error> {
        let seed = self.init_seed(&config, passphrase, create_new, false, None, short_seed)?;
        Ok(seed)
    }

    pub fn restore_seed(
        &self,
        config: &Wallet713Config,
        words: &Vec<&str>,
        passphrase: grin_util::ZeroingString,
    ) -> Result<(), Error> {
        WalletSeed::recover_from_phrase(
            &config.get_data_path_str()?,
            grin_util::ZeroingString::from(words.join(" ").as_str()),
            passphrase,
        )?;
        Ok(())
    }

    pub fn update_tip_as_last_scanned(&self) -> Result<(), Error> {
        let wallet_inst = self.get_wallet_instance()?;
        wallet_lock!(wallet_inst, w);
        let (tip_height, tip_hash, _) = w.w2n_client().get_chain_tip()?;
        let parent_key_id = w.parent_key_id();
        let mut batch = w.batch(None)?;
        batch.save_last_scanned_blocks(
            0,
            &vec![ScannedBlockInfo::new(tip_height, tip_hash.clone())],
        )?;
        batch.save_last_confirmed_height(&parent_key_id, tip_height)?;
        batch.commit()?;
        Ok(())
    }

    pub fn get_current_account(&self) -> Result<AcctPathMapping, Error> {
        Ok(api::get_current_account(self.get_wallet_instance()?)?)
    }

    pub fn list_accounts(&self) -> Result<(), Error> {
        let acct_mappings = api::accounts(self.get_wallet_instance()?)?;
        display::accounts(acct_mappings);
        Ok(())
    }

    pub fn rename_account(&self, old_name: &str, new_name: &str) -> Result<(), Error> {
        api::rename_account_path(self.get_wallet_instance()?, old_name, new_name)?;
        Ok(())
    }

    pub fn create_account(&self, name: &str) -> Result<(), Error> {
        api::create_account_path(self.get_wallet_instance()?, name)?;
        Ok(())
    }

    pub fn switch_account(&mut self, name: &str) -> Result<(), Error> {
        api::set_current_account(self.get_wallet_instance()?, name)?;
        Ok(())
    }

    pub fn info(&self, refresh: bool, confirmations: u64) -> Result<(), Error> {
        let (mut validated, wallet_info) =
            api::retrieve_summary_info(self.get_wallet_instance()?, refresh, confirmations)?;
        if !refresh {
            validated = true;
        }
        display::info(
            &Some(self.get_current_account()?.label),
            &wallet_info,
            !refresh || validated,
            true,
        );
        Ok(())
    }

    pub fn get_height(&self) -> Result<u64, Error> {
        let wallet_inst = self.get_wallet_instance()?;
        match api::node_height(wallet_inst.clone()) {
            Ok((h, _)) => return Ok(h),
            Err(_) => {
                wallet_lock!(wallet_inst, w);
                return Ok(w.last_confirmed_height()?);
            }
        }
    }

    pub fn get_id(&self, slate_id: Uuid) -> Result<u32, Error> {
        // guess height is needed to check node online status.
        let (_height, _) = api::node_height(self.get_wallet_instance()?)?;
        let id = api::retrieve_tx_id_by_slate_id(self.get_wallet_instance()?, slate_id)?;
        Ok(id)
    }

    pub fn txs_count(&self) -> Result<usize, Error> {
        let (_, txs) = api::retrieve_txs_with_proof_flag(
            self.get_wallet_instance()?,
            false,
            None,
            None,
            None,
            None,
        )?;
        Ok(txs.len())
    }

    pub fn txs(
        &self,
        refresh_from_node: bool,
        show_full_info: bool,
        pagination_start: Option<u32>,
        pagination_length: Option<u32>,
        tx_id: Option<u32>, // display single tx with all details
        tx_slate_id: Option<Uuid>,
    ) -> Result<(), Error> {
        let wallet_inst = self.get_wallet_instance()?;

        let height = if refresh_from_node {
            let (h, _) = api::node_height(wallet_inst.clone())?;
            h
        } else {
            wallet_lock!(wallet_inst, w);
            w.last_confirmed_height()?
        };

        let (validated, txs) = api::retrieve_txs_with_proof_flag(
            wallet_inst.clone(),
            refresh_from_node,
            tx_id.clone(),
            tx_slate_id.clone(),
            pagination_start,
            pagination_length,
        )?;
        let mut txs = txs
            .iter()
            .map(|tpl| tpl.0.clone())
            .collect::<Vec<TxLogEntry>>();

        let data_dir = {
            wallet_lock!(wallet_inst, w);
            String::from(w.get_data_file_dir())
        };

        // if given a particular transaction id or uuid, also get and display associated
        // inputs/outputs and messages
        let id = if tx_id.is_some() {
            tx_id
        } else if tx_slate_id.is_some() {
            if let Some(tx) = txs.iter().find(|t| t.tx_slate_id == tx_slate_id) {
                Some(tx.id)
            } else {
                println!("Could not find a transaction matching given tx Uuid.\n");
                None
            }
        } else {
            None
        };

        if let Some(id) = id {
            // Filter txs records. If we mess up with self transactions, we migth have several with same uuid.
            // The first one will be good for us.
            txs.retain(|tx| tx.id == id);
        }

        display::txs(
            &Some(self.get_current_account()?.label),
            height,
            !refresh_from_node || validated,
            &txs,
            true,
            true,
            show_full_info || id.is_some(),
            move |tx: &TxLogEntry| {
                let slate_id = match tx.tx_slate_id {
                    Some(m) => format!("{}", m),
                    None => return false,
                };
                TxProof::has_stored_tx_proof(&data_dir, &slate_id).unwrap_or(false)
            },
        )?;

        if txs.len() != 1 {
            return Ok(());
        }

        if id.is_some() {
            let (_, outputs) = self.retrieve_outputs(true, false, Some(&txs[0]))?;
            display::outputs(
                &Some(self.get_current_account()?.label),
                height,
                !refresh_from_node || validated,
                outputs,
                true,
            )?;
            debug_assert!(txs.len() == 1);
            let secp = Secp256k1::with_caps(ContextFlag::None);
            // should only be one here, but just in case
            for tx in txs {
                display::tx_messages(&tx, true, &secp)?;
                display::payment_proof(&tx)?;
            }
        }

        Ok(())
    }

    pub fn txs_bulk_validate(
        &self,
        kernels_fn: &str,
        outputs_fn: &str,
        result_fn: &str,
    ) -> Result<(), Error> {
        api::txs_bulk_validate(
            self.get_wallet_instance()?,
            kernels_fn,
            outputs_fn,
            result_fn,
        )?;
        Ok(())
    }

    pub fn total_value(
        &self,
        refresh_from_node: bool,
        minimum_confirmations: u64,
        output_list: &Option<Vec<String>>,
    ) -> Result<u64, Error> {
        let mut value = 0;
        let w = self.get_wallet_instance()?;

        let (height, _) = api::node_height(w.clone())?;
        let (_validated, outputs) =
            api::retrieve_outputs(w.clone(), false, refresh_from_node, None, None, None)?;

        if output_list.is_some() {
            let ol = output_list.clone().unwrap();
            for o in outputs {
                if o.output.eligible_to_spend(height, minimum_confirmations) {
                    let commit_str = o.output.commit.clone().unwrap();
                    if ol.iter().any(|e| *e == commit_str) {
                        value += o.output.value;
                    }
                }
            }
        } else {
            for o in outputs {
                if o.output.eligible_to_spend(height, minimum_confirmations) {
                    value += o.output.value;
                }
            }
        }

        Ok(value)
    }

    pub fn all_output_count(&self, show_spent: bool) -> Result<usize, Error> {
        let (_, outputs) = api::retrieve_outputs(
            self.get_wallet_instance()?,
            show_spent,
            false,
            None,
            None,
            None,
        )?;
        Ok(outputs.len())
    }

    pub fn output_count(
        &self,
        refresh_from_node: bool,
        minimum_confirmations: u64,
        output_list: &Option<Vec<String>>,
    ) -> Result<usize, Error> {
        let wallet = self.get_wallet_instance()?;

        let mut count = 0;

        let (height, _) = api::node_height(wallet.clone())?;
        let (_validated, outputs) =
            api::retrieve_outputs(wallet.clone(), false, refresh_from_node, None, None, None)?;

        if output_list.is_some() {
            let ol = output_list.clone().unwrap();
            for o in outputs {
                if o.output.eligible_to_spend(height, minimum_confirmations) {
                    let commit_str = o.output.commit.clone().unwrap();
                    if ol.iter().any(|e| *e == commit_str) {
                        count = count + 1;
                    }
                }
            }
        } else {
            for o in outputs {
                if o.output.eligible_to_spend(height, minimum_confirmations) {
                    count = count + 1;
                }
            }
        }

        Ok(count)
    }

    pub fn outputs(
        &self,
        refresh_from_node: bool,
        show_spent: bool,
        pagination_start: Option<u32>,
        pagination_length: Option<u32>,
    ) -> Result<(), Error> {
        let wallet = self.get_wallet_instance()?;

        let height = if refresh_from_node {
            let (h, _) = api::node_height(wallet.clone())?;
            h
        } else {
            wallet_lock!(wallet, w);
            w.last_confirmed_height()?
        };

        let (validated, outputs) = api::retrieve_outputs(
            wallet,
            show_spent,
            refresh_from_node,
            None,
            pagination_start,
            pagination_length,
        )?;
        display::outputs(
            &Some(self.get_current_account()?.label),
            height,
            !refresh_from_node || validated,
            outputs,
            true,
        )?;
        Ok(())
    }

    // Create slate but not lock outptus into the DB. Call tx_lock_outputs to do that
    pub fn init_send_tx(
        &self,
        address: Option<String>,
        amount: u64,
        minimum_confirmations: u64,
        selection_strategy: &str,
        change_outputs: u32,
        max_outputs: u32,
        message: Option<String>,
        outputs: Option<Vec<String>>,
        version: Option<u16>,
        routputs: usize,
        status_send_channel: &Option<Sender<StatusMessage>>,
        ttl_blocks: u64,
        do_proof: bool,
        slatepack_recipient: Option<ProvableAddress>,
        late_lock: Option<bool>,
        min_fee: Option<u64>,
        amount_includes_fee: bool,
    ) -> Result<Slate, Error> {
        let slate = api::init_send_tx(
            self.get_wallet_instance()?,
            None,
            address.clone(),
            amount,
            minimum_confirmations,
            max_outputs,
            change_outputs,
            selection_strategy == "all",
            message,
            outputs,
            version,
            routputs,
            status_send_channel,
            ttl_blocks,
            do_proof,
            slatepack_recipient,
            late_lock,
            min_fee,
            amount_includes_fee,
        )?;

        Ok(slate)
    }

    // Create invoice transaction
    pub fn initiate_receive_tx(
        &self,
        address: Option<String>,
        amount: u64,
        num_outputs: usize,
        slatepack_recipient: Option<ProvableAddress>,
    ) -> Result<Slate, Error> {
        let slate = api::initiate_receive_tx(
            self.get_wallet_instance()?,
            address,
            None,
            amount,
            num_outputs,
            None,
            slatepack_recipient,
        )?;
        Ok(slate)
    }

    pub fn repost(&self, id: u32, fluff: bool) -> Result<(), Error> {
        let wallet = self.get_wallet_instance()?;
        let (_validated, txs) =
            api::retrieve_txs_with_proof_flag(wallet.clone(), false, Some(id), None, None, None)?;
        let txs = txs
            .iter()
            .map(|tpl| tpl.0.clone())
            .collect::<Vec<TxLogEntry>>();
        if txs.len() == 0 {
            return Err(Error::GenericError(format!(
                "could not find transaction with id {}!",
                id
            )))?;
        }
        let slate_id = txs[0].tx_slate_id;
        if let Some(slate_id) = slate_id {
            let stored_tx = api::get_stored_tx(wallet.clone(), &slate_id.to_string())?;
            api::post_tx(wallet, &stored_tx, fluff)?;
        } else {
            Err(Error::GenericError(format!(
                "no transaction data stored for id {}, can not repost!",
                id
            )))?
        }

        Ok(())
    }

    pub fn cancel(&self, id: u32) -> Result<(), Error> {
        api::cancel_tx(self.get_wallet_instance()?, Some(id), None)?;
        Ok(())
    }

    pub fn restore_state(&self) -> Result<(), Error> {
        match api::restore(self.get_wallet_instance()?) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.to_string().contains("Node not ready or not available") {
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        }
    }

    pub fn check_repair(&self, start_height: u64, delete_unconfirmed: bool) -> Result<(), Error> {
        api::check_repair(
            self.get_wallet_instance()?,
            start_height,
            delete_unconfirmed,
        )?;
        Ok(())
    }

    pub fn sync(&self) -> Result<bool, Error> {
        let res = api::sync(self.get_wallet_instance()?, true)?;
        Ok(res)
    }

    pub fn dump_wallet_data(&self, file_name: Option<String>) -> Result<(), Error> {
        api::dump_wallet_data(self.get_wallet_instance()?, file_name)?;
        Ok(())
    }

    pub fn process_sender_initiated_slate(
        &self,
        address: Option<String>,
        slate: &mut Slate,
        message: Option<String>,
        key_id: Option<&str>,
        output_amounts: Option<Vec<u64>>,
        dest_acct_name: Option<&str>,
    ) -> Result<(), Error> {
        let s = api::receive_tx(
            self.get_wallet_instance()?,
            address,
            slate,
            message,
            key_id,
            output_amounts,
            dest_acct_name,
        )
        .map_err(|e| Error::GrinWalletReceiveError(format!("{}", e)))?;
        *slate = s;
        Ok(())
    }

    // Lock slate outputs. In other words create output and transaction record at the DB.
    pub fn tx_lock_outputs(
        &self,
        slate: &Slate,
        address: Option<String>,
        participant_id: usize,
    ) -> Result<(), Error> {
        api::tx_lock_outputs(self.get_wallet_instance()?, slate, address, participant_id)?;
        Ok(())
    }

    pub fn submit(&self, txn: &mut Transaction, fluff: bool) -> Result<(), Error> {
        api::post_tx(self.get_wallet_instance()?, &txn, fluff)
            .map_err(|e| Error::GrinWalletPostError(format!("{}", e)))?;
        Ok(())
    }

    pub fn finalize_post_slate(&self, slate: &mut Slate, fluff: bool) -> Result<(), Error> {
        let wallet = self.get_wallet_instance()?;
        api::verify_slate_messages(&slate)
            .map_err(|e| Error::GrinWalletVerifySlateMessagesError(format!("{}", e)))?;
        api::finalize_tx(wallet.clone(), slate)
            .map_err(|e| Error::GrinWalletFinalizeError(format!("{}", e)))?;
        if slate.tx.is_none() {
            return Err(Error::ArgumentError("Submitted slate is empty".to_string()));
        }
        api::post_tx(wallet, slate.tx.as_ref().unwrap(), fluff)
            .map_err(|e| Error::GrinWalletPostError(format!("{}", e)))?;
        Ok(())
    }

    pub fn retrieve_outputs(
        &self,
        include_spent: bool,
        refresh_from_node: bool,
        tx: Option<&TxLogEntry>,
    ) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
        let result = api::retrieve_outputs(
            self.get_wallet_instance()?,
            include_spent,
            refresh_from_node,
            tx,
            None,
            None,
        )?;
        Ok(result)
    }

    pub fn get_tx_proof(&self, id: u32) -> Result<TxProof, Error> {
        let res = api::get_stored_tx_proof(self.get_wallet_instance()?, id)?;
        Ok(res)
    }

    // pub fn verify_tx_proof(
    //     &self,
    //     tx_proof: &TxProof,
    // ) -> Result<(Option<String>, String, u64, Vec<String>, String), Error> {
    //     let (sender, receiver, amount, outputs, excess_sum) = api::verify_tx_proof(tx_proof)?;
    //
    //     let outputs = outputs
    //         .iter()
    //         .map(|o| grin_util::to_hex(o.0.to_vec()))
    //         .collect();
    //
    //     Ok((
    //         sender.map(|a| a.public_key.clone()),
    //         receiver.public_key.clone(),
    //         amount,
    //         outputs,
    //         excess_sum.to_hex(),
    //     ))
    // }

    pub fn swap_create_from_offer(&self, filename: String) -> Result<String, Error> {
        api::swap_create_from_offer(self.get_wallet_instance()?, filename)
    }

    pub fn swap_start(
        &self,
        mwc_amount: u64,
        outputs: Option<Vec<String>>,
        secondary_currency: String,
        secondary_amount: String,
        secondary_redeem_address: String,
        secondary_fee: Option<f32>,
        seller_lock_first: bool,
        minimum_confirmations: Option<u64>,
        mwc_confirmations: u64,
        secondary_confirmations: u64,
        message_exchange_time_sec: u64,
        redeem_time_sec: u64,
        buyer_communication_method: String,
        buyer_communication_address: String,
        electrum_node_uri1: Option<String>,
        electrum_node_uri2: Option<String>,
        eth_swap_contract_address: Option<String>,
        erc20_swap_contract_address: Option<String>,
        eth_infura_project_id: Option<String>,
        eth_redirect_to_private_wallet: Option<bool>,
        dry_run: bool,
        tag: Option<String>,
    ) -> Result<String, Error> {
        api::swap_start(
            self.get_wallet_instance()?,
            mwc_amount,
            outputs,
            secondary_currency,
            secondary_amount,
            secondary_redeem_address,
            secondary_fee,
            seller_lock_first,
            minimum_confirmations,
            mwc_confirmations,
            secondary_confirmations,
            message_exchange_time_sec,
            redeem_time_sec,
            buyer_communication_method,
            buyer_communication_address,
            electrum_node_uri1,
            electrum_node_uri2,
            eth_swap_contract_address,
            erc20_swap_contract_address,
            eth_infura_project_id,
            eth_redirect_to_private_wallet,
            dry_run,
            tag,
        )
    }

    pub fn get_provable_address(
        &self,
        addr_type: ProofAddressType,
    ) -> Result<ProvableAddress, Error> {
        api::get_provable_address(self.get_wallet_instance()?, addr_type)
    }

    pub fn get_payment_proof_address_pubkey(&self) -> Result<PublicKey, Error> {
        api::get_payment_proof_address_pubkey(self.get_wallet_instance()?)
    }

    pub fn get_payment_proof_address_secret(&self) -> Result<SecretKey, Error> {
        api::get_payment_proof_address_secret(self.get_wallet_instance()?)
    }

    pub fn deserialize_slate(
        &self,
        slate_str: &str,
    ) -> Result<
        (
            Slate,
            Option<SlatePurpose>,
            Option<DalekPublicKey>,
            Option<DalekPublicKey>,
        ),
        Error,
    > {
        api::deserialize_slate(self.get_wallet_instance()?, slate_str)
    }

    pub fn serialize_slate(
        &self,
        slate: &Slate,
        content: SlatePurpose,
        receiver: Option<DalekPublicKey>,
        slatepack_format: bool,
    ) -> Result<String, Error> {
        api::serialize_slate(
            self.get_wallet_instance()?,
            slate,
            content,
            receiver,
            slatepack_format,
        )
    }

    pub fn get_slatepack_keys(&self) -> Result<(DalekSecretKey, DalekPublicKey), Error> {
        let wallet = self.get_wallet_instance()?;
        wallet_lock!(wallet, w);
        let keychain = w.keychain(None)?;
        let secret = proofaddress::payment_proof_address_dalek_secret(&keychain, None)?;
        let pk = DalekPublicKey::from(&secret);
        Ok((secret, pk))
    }

    fn init_seed(
        &self,
        config: &Wallet713Config,
        passphrase: grin_util::ZeroingString,
        create_new: bool,
        create_file: bool,
        seed: Option<WalletSeed>,
        short_seed: bool
    ) -> Result<WalletSeed, Error> {
        let data_file_dir = config.get_data_path_str()?;
        let result = WalletSeed::from_file(&data_file_dir, passphrase.clone());
        let seed_lenght = match short_seed {
            true => 16,
            false => 32
        };
        let seed = match result {
            Ok(seed) => seed,
            Err(_) => {
                // could not load from file, let's create a new one
                if create_new {
                    WalletSeed::init_file_impl(
                        &data_file_dir,
                        seed_lenght,
                        None,
                        passphrase,
                        create_file,
                        !create_file,
                        seed,
                        false,
                    )?
                } else {
                    return Err(Error::WalletSeedCouldNotBeOpened);
                }
            }
        };
        Ok(seed)
    }

    // has full type because we don't want to deal with types inference.
    pub fn get_wallet_instance(
        &self,
    ) -> Result<
        Arc<
            Mutex<
                Box<
                    dyn WalletInst<
                        'static,
                        DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
                        HTTPNodeClient,
                        ExtKeychain,
                    >,
                >,
            >,
        >,
        Error,
    > {
        if let Some(ref backend) = self.backend {
            Ok(backend.clone())
        } else {
            Err(Error::NoWallet)
        }
    }

    fn create_wallet_instance(
        &mut self,
        config: &Wallet713Config,
        account: &str,
        passphrase: grin_util::ZeroingString,
    ) -> Result<(), Error> {
        //parse the node_uri String to a list
        //parse the nodes address and put them in a vec
        let node_list_string = &config.mwc_node_uri().clone();
        let node_list: Vec<String> = node_list_string
            .split(";")
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut node_client = HTTPNodeClient::new(node_list, config.mwc_node_secret())
            .map_err(|e| Error::HttpRequest(format!("Unable create Node Client, {}", e)))?;

        let _ = WalletSeed::from_file(&config.get_data_path_str()?, passphrase.clone())?;

        let mut wallet = Box::new(
            DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone()).unwrap(),
        )
            as Box<
                dyn WalletInst<
                    'static,
                    DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
                    HTTPNodeClient,
                    ExtKeychain,
                >,
            >;
        let lc = wallet.lc_provider().unwrap();
        lc.set_top_level_directory(config.get_top_level_directory()?.as_str())?;
        let mask = lc.open_wallet(
            None,
            passphrase,
            false,
            false,
            Some(config.get_wallet_data_directory()?.as_str()),
        )?;
        let wallet_inst = lc.wallet_inst()?;
        wallet_inst.set_parent_key_id_by_name(account)?;

        grin_wallet_libwallet::swap::trades::init_swap_trade_backend(
            wallet_inst.get_data_file_dir(),
            &config.swap_electrumx_addr,
            &config.swap_eth_contract_addr,
            &config.swap_erc20_contract_addr,
            &config.swap_eth_infura_project_id,
        );
        //read or save the node index(the good node)
        {
            let mut batch = wallet_inst.batch(mask.as_ref())?;
            let index = batch.get_last_working_node_index()?;
            if index == 0 {
                let _get_index = node_client.get_version_info(); //need to call a node api to get the working node index, one time cost.
                let node_client_index = node_client.get_node_index();
                let _ = batch.save_last_working_node_index(node_client_index + 1);
            //index stored in db start from 1. need to offset by +1
            } else {
                node_client.set_node_index(index - 1); //index stored in db start from 1. need to offset by -1
            }
            batch.commit()?;
        }

        self.backend = Some(Arc::new(Mutex::new(wallet)));

        match config.wallet_updater_frequency_sec {
            Some(freq) => {
                let handler = self.start_updater(None, Duration::from_secs(freq as u64))?;
                self.updater_handler = Some(handler);
            }
            _ => (),
        }

        Ok(())
    }

    fn start_updater(
        &self,
        keychain_mask: Option<&SecretKey>,
        frequency: Duration,
    ) -> Result<JoinHandle<()>, Error> {
        self.updater_running.store(true, Ordering::Relaxed);

        let updater =
            owner_updater::Updater::new(self.get_wallet_instance()?, self.updater_running.clone());

        let keychain_mask = match keychain_mask {
            Some(m) => Some(m.clone()),
            None => None,
        };

        let tx_inner = None;
        /* Uncomment it if you want to see progress in the output.
           It is commented because output distract only and will not make user happy.

        use std::sync::mpsc::channel;

        let (tx, rx) = channel();
        grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx)?;

        let tx_inner = Some(tx);*/

        let thread = thread::Builder::new()
            .name("wallet-updater".to_string())
            .spawn(move || {
                if let Err(e) = updater.run(frequency, keychain_mask, &tx_inner) {
                    error!("Wallet state updater failed with error: {:?}", e);
                }
            })?;
        Ok(thread)
    }
}
