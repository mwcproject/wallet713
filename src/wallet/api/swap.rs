use failure::Error;
use grinswap::{
	Action,
	Context,
	Currency,
	Status,
        SwapApi,
};

use CONTEXT;
use grinswap::Swap;
use super::keys;
use common::config::Wallet713Config;
use wallet::types::wallet_backend::WalletBackend;
use wallet::types::output_status::OutputStatus;
use broker::types::Publisher;
use broker::types::ContextHolderType;
use crate::broker::MWCMQPublisher;
use grin_p2p::types::PeerInfoDisplay;
use std::collections::HashMap;
use blake2_rfc::blake2b::blake2b;
use libwallet::NodeClient;
use wallet::types::HTTPNodeClient;
use crate::bitcoin::util::key::PublicKey as BtcPublicKey;
use grin_core::core::transaction::Weighting;
use grin_core::core::verifier_cache::LruVerifierCache;
use grin_core::core::{Transaction, TxKernel};
use grinswap::swap::message::Message;
use grinswap::swap::message::Update;
use grin_core::ser::{deserialize};
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use crate::grin_keychain::Identifier;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::{from_hex, to_hex};
use crate::bitcoin::{Address};
use bitcoin::network::constants::Network as BtcNetwork;
use parking_lot::{Mutex, RwLock};
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;

use grinswap::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient};

pub struct ContextHolder {
    pub context: Context,
    pub stored: bool,
    pub swap: Swap,
}

impl ContextHolderType for ContextHolder {
     fn get_context(&mut self) -> Option<&Context> {
        if !self.stored {
            return None;
        } else {
            return Some(&mut self.context);
        }
    }

    fn get_objs(&mut self) -> Option<(&Context,&mut Swap)> {
        if !self.stored {
            return None;
        } else {
            return Some((&mut self.context, &mut self.swap));
        }
    }

    fn set_context(&mut self, ctx: Context) {
        self.context = ctx;
        self.stored = true;
    }

    fn set_swap(&mut self, swap: Swap) {
        self.swap = swap;
    }

    fn get_swap(&mut self) -> Option<&mut Swap> {
        if !self.stored {
            return None;
        } else {
            return Some(&mut self.swap);
        }
    }
}

	fn _keychain(idx: u8) -> ExtKeychain {
		let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
		let seed_sell = blake2b(32, &[], seed_sell.as_bytes());
		ExtKeychain::from_seed(seed_sell.as_bytes(), false).unwrap()
	}
/*
pub fn select_coins<T: ?Sized, C, K>(wallet: &mut T, needed: u64) -> Result<Vec<OutputData>, Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
        let parent_key_id = wallet.get_parent_key_id();
        let height = wallet.w2n_client().get_chain_height()?;

        let (_, coins) =
                selection::select_coins(wallet, needed, height, 10, 500, false, &parent_key_id, None);
        let total = coins.iter().map(|c| c.value).sum();
        if total < needed {
                return Err(ErrorKind::NotEnoughFunds {
                        available: total,
                        available_disp: amount_to_hr_string(total, false),
                        needed,
                        needed_disp: amount_to_hr_string(needed, false),
                }
                .into());
        }

        Ok(coins)
}
*/


        #[derive(Debug, Clone)]
        struct TestNodeClientState {
                pub height: u64,
                pub pending: Vec<Transaction>,
                pub outputs: HashMap<Commitment, u64>,
                pub kernels: HashMap<Commitment, (TxKernel, u64)>,
        }

        #[derive(Debug, Clone)]
        struct TestNodeClient {
                pub state: Arc<Mutex<TestNodeClientState>>,
        }

impl libwallet::NodeClient for TestNodeClient {
        /// Return total_difficulty of the chain
        fn get_total_difficulty(&self) -> Result<u64, libwallet::Error> {
                        unimplemented!()
        }

        /// Return Connected peers
        fn get_connected_peer_info(&self) -> Result<Vec<PeerInfoDisplay>, libwallet::Error> {
                        unimplemented!()
        }

                fn node_url(&self) -> &str {
                        unimplemented!()
                }
                fn set_node_url(&mut self, _node_url: &str) {
                        unimplemented!()
                }
                fn node_api_secret(&self) -> Option<String> {
                        unimplemented!()
                }
                fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {
                        unimplemented!()
                }
                fn post_tx(&self, tx: &libwallet::TxWrapper, _fluff: bool) -> Result<(), libwallet::Error> {
                        let wrapper = from_hex(tx.tx_hex.clone()).unwrap();
                        let mut cursor = Cursor::new(wrapper);
                        let tx: Transaction = deserialize(&mut cursor).unwrap();
                        tx.validate(
                                Weighting::AsTransaction,
                                Arc::new(RwLock::new(LruVerifierCache::new())),
                        )
                        .map_err(|_| libwallet::ErrorKind::Node)?;

                        let mut state = self.state.lock();
                        for input in tx.inputs() {
                                // Output not unspent
                                if !state.outputs.contains_key(&input.commit) {
                                        return Err(libwallet::ErrorKind::Node.into());
                                }

                                // Double spend attempt
                                for tx_pending in state.pending.iter() {
                                        for in_pending in tx_pending.inputs() {
                                                if in_pending.commit == input.commit {
                                                        return Err(libwallet::ErrorKind::Node.into());
                                                }
                                        }
                                }
                        }
                        // Check for duplicate output
                        for output in tx.outputs() {
                                if state.outputs.contains_key(&output.commit) {
                                        return Err(libwallet::ErrorKind::Node.into());
                                }

                                for tx_pending in state.pending.iter() {
                                        for out_pending in tx_pending.outputs() {
                                                if out_pending.commit == output.commit {
                                                        return Err(libwallet::ErrorKind::Node.into());
                                                }
                                        }
                                }
                        }
                        // Check for duplicate kernel
                        for kernel in tx.kernels() {
                                // Duplicate kernel
                                if state.kernels.contains_key(&kernel.excess) {
                                        return Err(libwallet::ErrorKind::Node.into());
                                }

                                for tx_pending in state.pending.iter() {
                                        for kernel_pending in tx_pending.kernels() {
                                                if kernel_pending.excess == kernel.excess {
                                                        return Err(libwallet::ErrorKind::Node.into());
                                                }
                                        }
                                }
                        }
                        state.pending.push(tx);

                        Ok(())
                }
                fn get_version_info(&mut self) -> Option<libwallet::NodeVersionInfo> {
                        unimplemented!()
                }
                fn get_chain_height(&self) -> Result<u64, libwallet::Error> {
                        Ok(self.state.lock().height)
                }

                fn get_outputs_from_node(
                        &self,
                        wallet_outputs: Vec<Commitment>,
                ) -> Result<HashMap<Commitment, (String, u64, u64)>, libwallet::Error> {
                        let mut map = HashMap::new();
                        let state = self.state.lock();
                        for output in wallet_outputs {
                                if let Some(height) = state.outputs.get(&output) {
                                        map.insert(output, (to_hex(output.0.to_vec()), *height, 0));
                                }
                        }
                        Ok(map)
                }
                fn get_outputs_by_pmmr_index(
                        &self,
                        _start_height: u64,
                        _max_outputs: u64,
                ) -> Result<(u64, u64, Vec<(Commitment, RangeProof, bool, u64, u64)>), libwallet::Error> {
                        unimplemented!()
                }
                fn get_kernel(
                        &mut self,
                        excess: &Commitment,
                        _min_height: Option<u64>,
                        _max_height: Option<u64>,
                ) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
                        let state = self.state.lock();
                        let res = state
                                .kernels
                                .get(excess)
                                .map(|(kernel, height)| (kernel.clone(), *height, 0));
                        Ok(res)
                }
        }



pub struct SwapProcessor {
}


impl SwapProcessor
{

fn context_sell<T: ?Sized, C, K>(&self,
                                 wallet: &mut T,
                                 api_sell: &mut BtcSwapApi::<K, HTTPNodeClient, ElectrumNodeClient>) -> Context
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    let inputs = wallet.outputs();
    let mut input_vec: Vec<(Identifier, u64)> = vec![];
    for input in inputs {
        if input.status == OutputStatus::Unspent {
            input_vec.push((input.key_id, input.value));
        }
    }

    // Generate the appropriate amount of derivation paths
    let key_count = api_sell.context_key_count(Currency::Btc, true).unwrap();
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let id = keys::next_available_key(&mut *wallet).unwrap();
        keys.push(id);
    }

    api_sell.create_context(Currency::Btc, true, Some(input_vec), keys).unwrap()
}

        fn key<K>(&self, kc: &K, d1: u32, d2: u32) -> SecretKey
        where
                K: Keychain
        {
                kc.derive_key(0, &self.key_id(d1, d2), &SwitchCommitmentType::None)
                        .unwrap()
        }

        fn key_id(&self, d1: u32, d2: u32) -> Identifier {
                ExtKeychain::derive_key_id(2, d1, d2, 0, 0)
        }

        fn btc_address<K>(&self, kc: &K) -> String
        where
                K: Keychain
        {
                let key = PublicKey::from_secret_key(kc.secp(), &self.key(kc, 2, 0)).unwrap();
                let address = Address::p2pkh(
                        &BtcPublicKey {
                                compressed: true,
                                key,
                        },
                        BtcNetwork::Testnet,
                );
                format!("{}", address)
        }

fn context_buy<T: ?Sized, C, K>(&self, wallet: &mut T,
                                api_buy: &mut BtcSwapApi::<K, HTTPNodeClient, ElectrumNodeClient>) -> Context
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    // Generate the appropriate amount of derivation paths
    let key_count = api_buy.context_key_count(Currency::Btc, false).unwrap();
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let id = keys::next_available_key(&mut *wallet).unwrap();
        keys.push(id);
    }

    api_buy.create_context(Currency::Btc, false, None, keys).unwrap()
}

pub fn make_buy_btc<T: ?Sized, C, K>(&self, _wallet: &mut T, _rate: f64, _qty: u64)
-> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    println!("do make buy");

    Ok(())
}

pub fn make_sell_btc<T: ?Sized, C, K>(&self, _wallet: &mut T, _rate: f64, _qty: u64)
-> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    println!("do make sell");
    Ok(())

}

pub fn take_buy_btc<T: ?Sized, C, K>(&self, _wallet: &mut T, _rate: f64, _qty: u64, _address: &str)
-> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    println!("do take buy");
    Ok(())
}

pub fn take_sell_btc<T: ?Sized, C, K>(&self, wallet: &mut T, rate: f64, qty: u64, address: &str, publisher: &mut Publisher)
-> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    println!("do take sell");
    let keychain = wallet.keychain().clone();

    let btc_node_client = ElectrumNodeClient::new("3.92.132.156:8000".to_string(),
                                                grin_core::global::is_floonet());


    let btc_amount_sats = ((qty as f64 * rate / (1_000_000_000 as f64)) as f64 * 100_000_000 as f64) as u64;

    let client = HTTPNodeClient::new(
        "https://mwc713.floonet.mwc.mw",
        Some("11ne3EAUtOXVKwhxm84U".to_string()),
    );

    let mut api_sell = BtcSwapApi::<K, _, _>::new(Some(keychain.clone()),
                                                  client.clone(),
                                                  btc_node_client);

    let ctx = self.context_sell(wallet, &mut api_sell);

    let secondary_redeem_address = self.btc_address(&keychain);

    let (mut swap_sell, _action) = api_sell
                       .create_swap_offer(
                                &ctx,
                                None,
                                qty,
                                btc_amount_sats,
                                Currency::Btc,
                                secondary_redeem_address,
                        )
                        .unwrap();


    let message = api_sell.message(&swap_sell).unwrap();
    let _action = api_sell.message_sent(&mut swap_sell, &ctx).unwrap();

    let res = publisher.post_take(&message, address);

    if res.is_err() {
        println!("Error processing post_take: {:?}", res);
    }
println!("post pub");
    let mut context_static = (&CONTEXT).lock();
println!("saving ctx= {:?}", ctx);
    context_static.set_context(ctx);
println!("mmm");
   //(&mut(*context_holder)).set_context(ctx);

    //println!("action = {:?}, message = {}", action, serde_json::to_string_pretty(&message).unwrap());
    println!("swap sell tx = {:?}", swap_sell.lock_slate.tx);
    println!("btc_amount for trade in satoshis = {}", btc_amount_sats);

    context_static.set_swap(swap_sell);


    Ok(())
}

pub fn process_offer<T: ?Sized, C, K>(&self,
                             wallet: &mut T,
                             from: &dyn crate::contacts::types::Address,
                             message: Message,
                             _config: Option<Wallet713Config>,
                             publisher: &mut Publisher,
) -> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
    let keychain = wallet.keychain().clone();
    let btc_node_client = ElectrumNodeClient::new("3.92.132.156:8000".to_string(),
                                                grin_core::global::is_floonet());
    let client = HTTPNodeClient::new(
        "https://mwc713.floonet.mwc.mw",
        Some("11ne3EAUtOXVKwhxm84U".to_string()),
    );
println!("1");
    let mut api_buy = BtcSwapApi::<K, _, _>::new(Some(keychain.clone()), client.clone(), btc_node_client);
println!("2");
    let ctx_buy = self.context_buy(wallet, &mut api_buy);
println!("3");
    let (mut swap_buy, action) = api_buy
                        .accept_swap_offer(&ctx_buy, None, message)
                        .unwrap();
println!("4");
    assert_eq!(swap_buy.status, Status::Offered);
    assert_eq!(action, Action::SendMessage(1));
    let accepted_message = api_buy.message(&swap_buy).unwrap();
println!("5");
    let action = api_buy.message_sent(&mut swap_buy, &ctx_buy).unwrap();
println!("6");

    let address = match action {

        Action::DepositSecondary { amount: _, address } => {
            //assert_eq!(amount, btc_amount);
            address
        }
        _ => panic!("Invalid action"),
    };

println!("7");

    assert_eq!(swap_buy.status, Status::Accepted);
    let address = Address::from_str(&address).unwrap();

    println!("offer accepted! send btc to {}", address);
   
    let res = publisher.post_take(&accepted_message, &from.stripped());

    if res.is_err() {
        println!("Error in post_take: {:?}", res);
    }

    Ok(())

}

pub fn process_accept_offer<T: ?Sized, C, K>(&self,
                             wallet: &mut T,
                             _from: &dyn crate::contacts::types::Address,
                             message: Message,
                             _config: Option<Wallet713Config>,
                             _publisher: &mut Publisher,
) -> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{
println!("in process_accept_offer");

    let keychain = wallet.keychain().clone();
    
    let btc_node_client = ElectrumNodeClient::new("3.92.132.156:8000".to_string(),
                                                grin_core::global::is_floonet());
    
    let client = HTTPNodeClient::new(
        "https://mwc713.floonet.mwc.mw",
        Some("11ne3EAUtOXVKwhxm84U".to_string()),
    );
    
    let mut api_sell = BtcSwapApi::<K, _, _>::new(Some(keychain.clone()),
                                                  client.clone(),
                                                  btc_node_client);
    let mut context_static = (&CONTEXT).lock();

    let (ctx_sell, mut swap_sell) = context_static.get_objs().unwrap();

    let action = api_sell
                        .receive_message(swap_sell, &ctx_sell, message)
                        .unwrap();
                assert_eq!(action, Action::PublishTx);
                assert_eq!(swap_sell.status, Status::Accepted);
    println!("receive message complete submitting to the newtork!");

   let action = api_sell
                .publish_transaction(&mut swap_sell, &ctx_sell)
                        .unwrap();


   match action {
       Action::Confirmations {
           required: _,
           actual,
       } => assert_eq!(actual, 0),
       _ => panic!("Invalid action"),
   }

   println!("successfully submitted");

    Ok(())
}


pub fn process_swap_message<T: ?Sized, C, K>(&self,
                             wallet: &mut T,
                             from: &dyn crate::contacts::types::Address,
                             message: Message,
                             config: Option<Wallet713Config>,
                             publisher: &mut Publisher,
) -> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{

    let _res = match &message.inner {
    	Update::AcceptOffer(_u) => self.process_accept_offer(wallet, from, message, config, publisher),
	Update::Offer(_u) => self.process_offer(wallet, from, message, config, publisher),
	_ => Err(libwallet::ErrorKind::Node.into()),
    }?;

    Ok(())
}

pub fn swap<T: ?Sized, C, K>(&self,
                             wallet: &mut T,
                             pair: &str,
                             is_make: bool,
                             is_buy: bool,
                             rate: f64,
                             qty: u64,
                             address: Option<&str>,
                             publisher: &mut MWCMQPublisher,
) -> Result<(), Error>
where
    T: WalletBackend<C, K>,
    C: NodeClient,
    K: grinswap::Keychain,
{

                    println!("Rate={}, Qty={}", rate, qty);
                    println!("ismake={:?}", is_make);
                    println!("pair={:?}", pair);
                    println!("is_buy={:?}", is_buy);
                    println!("address={:?}", address);

        	println!("swap swap swap");

                let _res = if is_make && is_buy {
                   self.make_buy_btc(wallet, rate, qty)
                } else if is_make && !is_buy {
                   self.make_sell_btc(wallet, rate, qty)
                } else if !is_make && is_buy {
                   self.take_buy_btc(wallet, rate, qty, address.unwrap())
                } else {
                   self.take_sell_btc(wallet, rate, qty, address.unwrap(), publisher)
                }?;

                /*
		let write_json = false;

                //let kc_sell = keychain(1);
		let kc_sell = wallet.keychain();
                let ctx_sell = context_sell(kc_sell);
                let secondary_redeem_address = btc_address(kc_sell);
                let nc = TestNodeClient::new(300_000);
                let btc_nc = TestBtcNodeClient::new(500_000);
                let amount = 100 * 1_000_000;
                let btc_amount_1 = 2_000_000;
                let btc_amount_2 = 1_000_000;
                let btc_amount = btc_amount_1 + btc_amount_2;

                // Seller: create swap offer
                let mut api_sell = BtcSwapApi::<K, _, _>::new(Some(kc_sell.clone()), nc.clone(), btc_nc.clone());
                let (mut swap_sell, action) = api_sell
                        .create_swap_offer(
                                &ctx_sell,
                                None,
                                amount,
                                btc_amount,
                                Currency::Btc,
                                secondary_redeem_address,
                        )
                        .unwrap();
                assert_eq!(action, Action::SendMessage(1));
                assert_eq!(swap_sell.status, Status::Created);
                let message_1 = api_sell.message(&swap_sell).unwrap();
                let action = api_sell.message_sent(&mut swap_sell, &ctx_sell).unwrap();
                assert_eq!(action, Action::ReceiveMessage);
                assert_eq!(swap_sell.status, Status::Offered);

		if write_json {
                        write(
                                "~/test/swap_sell_1.json",
                                serde_json::to_string_pretty(&swap_sell).unwrap(),
                        )
                        .unwrap();

                        write(
                                "~/test/message_1.json",
                                serde_json::to_string_pretty(&message_1).unwrap(),
                        )
                        .unwrap();
                        write(
                                "~/test/context_sell.json",
                                serde_json::to_string_pretty(&ctx_sell).unwrap(),
                        )
                        .unwrap();
                }
                // Add inputs to utxo set
                nc.mine_blocks(2);
                for input in swap_sell.lock_slate.tx.inputs() {
                        nc.push_output(input.commit.clone());
                }

                //let kc_buy = keychain(2);
		let kc_buy = kc_sell;
                let ctx_buy = context_buy(kc_buy);

                // Buyer: accept swap offer
                let mut api_buy = BtcSwapApi::<K, _, _>::new(Some(kc_buy.clone()), nc.clone(), btc_nc.clone());
                let (mut swap_buy, action) = api_buy
                        .accept_swap_offer(&ctx_buy, None, message_1)
                        .unwrap();
                assert_eq!(swap_buy.status, Status::Offered);
                assert_eq!(action, Action::SendMessage(1));
                let message_2 = api_buy.message(&swap_buy).unwrap();
                let action = api_buy.message_sent(&mut swap_buy, &ctx_buy).unwrap();

                // Buyer: should deposit bitcoin
                let address = match action {

                        Action::DepositSecondary { amount, address } => {
                                assert_eq!(amount, btc_amount);
                                address
                        }
                        _ => panic!("Invalid action"),
                };
                assert_eq!(swap_buy.status, Status::Accepted);
                let address = Address::from_str(&address).unwrap();

                // Buyer: first deposit
                let tx_1 = BtcTransaction {
                        version: 2,
                        lock_time: 0,
                        input: vec![],
                        output: vec![TxOut {
                                value: btc_amount_1,
                                script_pubkey: address.script_pubkey(),
                        }],
                };
                let txid_1 = tx_1.txid();
                btc_nc.push_transaction(&tx_1);

                match api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap() {
                        Action::DepositSecondary { amount, address: _ } => assert_eq!(amount, btc_amount_2),
                        _ => panic!("Invalid action"),
                };

                // Buyer: second deposit
                btc_nc.mine_blocks(2);
                let tx_2 = BtcTransaction {
                        version: 2,
                        lock_time: 0,
                        input: vec![],
                        output: vec![TxOut {
                                value: btc_amount_2,
                                script_pubkey: address.script_pubkey(),
                        }],
                };
                let txid_2 = tx_2.txid();
                btc_nc.push_transaction(&tx_2);
                match api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap() {
                        Action::ConfirmationsSecondary {
                                required: _,
                                actual,
                        } => assert_eq!(actual, 1),
                        _ => panic!("Invalid action"),
                };
                btc_nc.mine_blocks(5);

                // Buyer: wait for Grin confirmations
                match api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap() {
                        Action::Confirmations {
                                required: _,
                                actual,
                        } => assert_eq!(actual, 0),
                        _ => panic!("Invalid action"),
                };

                // Check if buyer has correct confirmed outputs
                {
                        let btc_data = swap_buy.secondary_data.unwrap_btc().unwrap();
                        assert_eq!(btc_data.confirmed_outputs.len(), 2);
                        let mut match_1 = 0;
                        let mut match_2 = 0;
                        for output in &btc_data.confirmed_outputs {
                                if output.out_point.txid == txid_1 {
                                        match_1 += 1;
                                }
                                if output.out_point.txid == txid_2 {
                                        match_2 += 1;
                                }
                        }
                        assert_eq!(match_1, 1);
                        assert_eq!(match_2, 1);
                }

                if write_json {
                        write(
                                "~/test/swap_buy_1.json",
                                serde_json::to_string_pretty(&swap_buy).unwrap(),
                        )
                        .unwrap();
			write(
        			"~/test/message_2.json",
                                serde_json::to_string_pretty(&message_2).unwrap(),
                        )
                        .unwrap();
                        write(
                                "~/test/context_buy.json",
                                serde_json::to_string_pretty(&ctx_buy).unwrap(),
                        )
                        .unwrap();
                }

                // Seller: receive accepted offer
                let action = api_sell
                        .receive_message(&mut swap_sell, &ctx_sell, message_2)
                        .unwrap();
                assert_eq!(action, Action::PublishTx);
                assert_eq!(swap_sell.status, Status::Accepted);
                let action = api_sell
                        .publish_transaction(&mut swap_sell, &ctx_sell)
                        .unwrap();
                match action {
                        Action::Confirmations {
                                required: _,
                                actual,
                        } => assert_eq!(actual, 0),
                        _ => panic!("Invalid action"),
                }

                if write_json {
                        write(
                                "test/swap_sell_2.json",
                                serde_json::to_string_pretty(&swap_sell).unwrap(),
                        )
                        .unwrap();
                }

                // Seller: wait for Grin confirmations
                nc.mine_blocks(10);
                match api_sell.required_action(&mut swap_sell, &ctx_sell).unwrap() {
                        Action::Confirmations {
                                required: _,
                                actual,
                        } => assert_eq!(actual, 10),
                        _ => panic!("Invalid action"),
                }


                // Buyer: wait for less Grin confirmations
                match api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap() {
                        Action::Confirmations {
                                required: _,
                                actual,
                        } => assert_eq!(actual, 10),
                        _ => panic!("Invalid action"),
                }

                // Undo a BTC block to test seller
                {
                        let mut state = btc_nc.state.lock();
                        state.height -= 1;
                }

                // Seller: wait BTC confirmations
                nc.mine_blocks(20);
                match api_sell.required_action(&mut swap_sell, &ctx_sell).unwrap() {
                        Action::ConfirmationsSecondary {
                                required: _,
                                actual,
                        } => assert_eq!(actual, 5),
                        _ => panic!("Invalid action"),
                }
                btc_nc.mine_block();

                if write_json {
                        write(
                                "test/swap_sell_3.json",
                                serde_json::to_string_pretty(&swap_sell).unwrap(),
                        )
                        .unwrap();
                }

                // Buyer: start redeem
                let action = api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap();
                assert_eq!(action, Action::SendMessage(2));
                assert_eq!(swap_buy.status, Status::Locked);
                let message_3 = api_buy.message(&swap_buy).unwrap();
                api_buy.message_sent(&mut swap_buy, &ctx_buy).unwrap();



                // Seller: sign redeem
                let action = api_sell.required_action(&mut swap_sell, &ctx_sell).unwrap();
                assert_eq!(action, Action::ReceiveMessage);
                assert_eq!(swap_sell.status, Status::Locked);
                let action = api_sell
                        .receive_message(&mut swap_sell, &ctx_sell, message_3)
                        .unwrap();
                assert_eq!(action, Action::SendMessage(2));
                assert_eq!(swap_sell.status, Status::InitRedeem);
                let message_4 = api_sell.message(&swap_sell).unwrap();
                let action = api_sell.message_sent(&mut swap_sell, &ctx_sell).unwrap();

                // Seller: wait for buyer's on-chain redeem tx
                assert_eq!(action, Action::ConfirmationRedeem);
                assert_eq!(swap_sell.status, Status::Redeem);

                if write_json {
                        write(
                                "test/swap_sell_4.json",
                                serde_json::to_string_pretty(&swap_sell).unwrap(),
                        )
                        .unwrap();
                        write(
                                "test/message_4.json",
                                serde_json::to_string_pretty(&message_4).unwrap(),
                        )
                        .unwrap();
                }

                // Buyer: redeem
                let action = api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap();
                assert_eq!(action, Action::ReceiveMessage);
                assert_eq!(swap_buy.status, Status::InitRedeem);
                let action = api_buy
                        .receive_message(&mut swap_buy, &ctx_buy, message_4)
                        .unwrap();
                assert_eq!(action, Action::PublishTx);
                assert_eq!(swap_buy.status, Status::Redeem);
                let action = api_buy
                        .publish_transaction(&mut swap_buy, &ctx_buy)
                        .unwrap();
                assert_eq!(action, Action::ConfirmationRedeem);

                // Buyer: complete!
                nc.mine_block();
                let action = api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap();
                assert_eq!(action, Action::Complete);
                // At this point, buyer would add Grin to their outputs
                let action = api_buy.completed(&mut swap_buy, &ctx_buy).unwrap();
                assert_eq!(action, Action::None);
                assert_eq!(swap_buy.status, Status::Completed);

                if write_json {
                        write(
                                "test/swap_buy_3.json",
                                serde_json::to_string_pretty(&swap_buy).unwrap(),
                        )
                        .unwrap();
                }

                // Seller: publish BTC tx
                let action = api_sell.required_action(&mut swap_sell, &ctx_sell).unwrap();
                assert_eq!(action, Action::PublishTxSecondary);
                assert_eq!(swap_sell.status, Status::RedeemSecondary);

                if write_json {
                        write(
                                "test/swap_sell_5.json",
                                serde_json::to_string_pretty(&swap_sell).unwrap(),
                        )
                        .unwrap();
                }

                // Seller: wait for BTC confirmations
                let action = api_sell
                        .publish_secondary_transaction(&mut swap_sell, &ctx_sell)
                        .unwrap();
                match action {
                        Action::ConfirmationRedeemSecondary(_) => {}
                        _ => panic!("Invalid action"),
                };

                // Seller: complete!
                btc_nc.mine_block();
                let action = api_sell.required_action(&mut swap_sell, &ctx_sell).unwrap();
                assert_eq!(action, Action::Complete);
                let action = api_sell.completed(&mut swap_sell, &ctx_sell).unwrap();
                assert_eq!(action, Action::None);
                assert_eq!(swap_sell.status, Status::Completed);

                if write_json {
                        write(
                                "test/swap_sell_6.json",
                                serde_json::to_string_pretty(&swap_sell).unwrap(),
                        )
                        .unwrap();
                }
  */
println!("swap complete");
        Ok(())
}

}
