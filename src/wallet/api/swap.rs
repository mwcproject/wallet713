use std::collections::HashMap;
use std::sync::Arc;
use std::str::FromStr;
use std::{mem, time, thread};
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs::{read_to_string, write, File};
use std::path::Path;
use std::{fs, path};
use std::io::{Read, Write};
use parking_lot::{ Mutex };
use blake2_rfc::blake2b::blake2b;
use uuid::Uuid;

use crate::bitcoin::{Address};
use crate::bitcoin::network::constants::Network as BtcNetwork;
use crate::bitcoin::util::key::PublicKey as BtcPublicKey;


use grin_wallet_impls::adapters::mwcmq::MWCMQPublisher;
use grin_wallet_impls::adapters::types::Publisher;
use grin_wallet_impls::adapters::types::ContextHolderType;
use grin_wallet_config::WalletConfig;
use common::{ErrorKind, Error};
use common::config::Wallet713Config;

use grinswap::{Context, Swap, Currency, Action, Status, SwapApi, BuyApi, SellApi};
use grinswap::swap::types::{ RoleContext, SecondarySellerContext, SellerContext, SecondaryBuyerContext, BuyerContext };
use grinswap::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient, BtcNodeClient, TestBtcNodeClient, BtcSellerContext, BtcBuyerContext };
use grinswap::swap::message::{ Message, Update };
use grin_core::core::{ Transaction, TxKernel };
use grin_p2p::types::PeerInfoDisplay;
use grin_util::secp::pedersen::{ Commitment, RangeProof };
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::{RwLock};
use grin_wallet_libwallet::{ NodeClient, HeaderInfo, WalletBackend, OutputStatus };
use grin_wallet_libwallet::internal::{updater,keys};
use grin_wallet_impls::node_clients::HTTPNodeClient;
use grin_keychain::{ExtKeychain, Keychain, Identifier, SwitchCommitmentType };

const GRIN_UNIT: u64 = 1_000_000_000;
pub const SWAP_DEAL_SAVE_DIR: &'static str = "saved_swap_deal";

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

    fn get_objs(&mut self) -> Option<(&Context, &mut Swap)> {
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

fn key_id(d1: u32, d2: u32) -> Identifier {
		ExtKeychain::derive_key_id(2, d1, d2, 0, 0)
}

fn context_sell(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Seller(SellerContext {
				inputs: vec![
					(key_id(0, 1), 60 * GRIN_UNIT),
					(key_id(0, 2), 60 * GRIN_UNIT),
				],
				change_output: key_id(0, 3),
				refund_output: key_id(0, 4),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: key_id(0, 5),
				}),
			}),
		}
}

fn context_buy(kc: &ExtKeychain) -> Context {
    Context {
        multisig_key: key_id(0, 0),
        multisig_nonce: key(kc, 1, 0),
        lock_nonce: key(kc, 1, 1),
        refund_nonce: key(kc, 1, 2),
        redeem_nonce: key(kc, 1, 3),
        role_context: RoleContext::Buyer(BuyerContext {
            output: key_id(0, 1),
            redeem: key_id(0, 2),
            secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
                refund: key_id(0, 3),
            }),
        }),
    }
}

fn key(kc: &ExtKeychain, d1: u32, d2: u32) -> SecretKey {
		kc.derive_key(0, &key_id(d1, d2), &SwitchCommitmentType::None)
			.unwrap()
}

fn _btc_address(kc: &ExtKeychain) -> String
{
    let key = PublicKey::from_secret_key(kc.secp(), &key(kc, 2, 0)).unwrap();
    let address = Address::p2pkh(
        &BtcPublicKey {
            compressed: true,
            key,
        },
        BtcNetwork::Testnet,
    );
    format!("{}", address)
}

// Init for file storage for saving swap deals
fn init_swap_backend(data_file_dir: &str) -> Result<(), Error> {
    let stored_swap_deal_path = path::Path::new(data_file_dir).join(SWAP_DEAL_SAVE_DIR);
    fs::create_dir_all(&stored_swap_deal_path)
        .expect("Could not create swap deal storage directory!");
    Ok(())
}

// Get swap deal from the storage
fn get_swap_deal(data_file_dir: &str, swap_id: &str) -> Result<Swap, Error> {
    let filename = format!("{}.swap", swap_id);
    let path = path::Path::new(data_file_dir)
                    .join(SWAP_DEAL_SAVE_DIR)
                    .join(filename);
    let swap_deal_file = Path::new(&path).to_path_buf();
    if !swap_deal_file.exists() {
        return Err(ErrorKind::SwapDealNotFoundError(
            swap_deal_file.to_str().unwrap_or(&"UNKNOWN").to_string(),
        ).into());
    }
    let mut swap_deal_f = File::open(swap_deal_file)?;
    let mut content = String::new();
    swap_deal_f.read_to_string(&mut content)?;

    Ok((serde_json::from_str(&content).map_err(|e| {
        ErrorKind::SwapDealGenericError(format!("Unable to get saved swap from Json, {}", e))
    }))?)
}

// Store swap deal to a file
fn store_swap_deal(swap: &Swap, data_file_dir: &str, swap_id: &str) -> Result<(), Error> {
    let filename = format!("{}.swap", swap_id);
    let path = path::Path::new(data_file_dir)
                    .join(SWAP_DEAL_SAVE_DIR)
                    .join(filename);
    let path_buf = Path::new(&path).to_path_buf();
    let mut stored_swap = File::create(path_buf)?;
    let swap_ser = serde_json::to_string(swap).map_err(|e| {
        ErrorKind::SwapDealGenericError(format!("Unable to convert swap to Json, {}", e))
    })?;
    stored_swap.write_all(&swap_ser.as_bytes())?;
    stored_swap.sync_all()?;
    Ok(())
}

pub fn make_sell_mwc<'a, T: ?Sized, C, K>(_wallet: &mut T,
                                          _rate: u64,
                                          _qty: u64,
                                          _btc_redeem: &str,
                                          config: &Wallet713Config,
                                          publisher: &mut Publisher
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    Ok(())
}

pub fn make_buy_mwc<'a, T: ?Sized, C, K>(_wallet: &mut T,
                                         _rate: u64,
                                         _qty: u64,
                                         config: &Wallet713Config,
                                         publisher: &mut Publisher
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    //let mut context_static = (&CONTEXT).lock();
    Ok(())
}

pub fn take_buy_mwc<'a, T: ?Sized, C, K>(_wallet: &mut T,
                                         _rate: u64,
                                         _qty: u64,
                                         _btc_redeem: &str,
                                         _address: &str,
                                         config: &Wallet713Config,
                                         publisher: &mut Publisher

) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    //let mut context_static = (&CONTEXT).lock();
    let node_client = HTTPNodeClient::new(
        &config.mwc_node_uri(),
        config.mwc_node_secret(),
    );

    let kc_buy = _keychain(1);
    let ctx_buy = context_buy(&kc_buy);

    let btc_node_client= ElectrumNodeClient::new(
        config.electrum_node_client().ok().expect("node missing"), true);
    let mut api_buy = BtcSwapApi::<_, _>::new(
        node_client.clone(), btc_node_client);

    let (mut swap_buy, action) = api_buy
        .create_swap_offer(
            &kc_buy,
            &ctx_buy,
            Some(_address.to_string()),
            _qty,
            _rate*_qty,
            Currency::Btc,
            _btc_redeem.to_owned(),
        ).unwrap();
    let message = api_buy.message(&kc_buy, &swap_buy).unwrap();
    let res = publisher.post_take(&message, _address);

    let action = api_buy.message_sent(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();
    assert_eq!(swap_buy.status, Status::Offered);

    Ok(())
}

pub fn take_sell_mwc<'a, T: ?Sized, C, K>(_wallet: &mut T,
                                          _rate: u64,
                                          _qty: u64,
                                          _btc_redeem: &str,
                                          _address: &str,
                                          config: &Wallet713Config,
                                          publisher: &mut Publisher
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    let node_client = HTTPNodeClient::new(
        &config.mwc_node_uri(),
        config.mwc_node_secret(),
    );
    let btc_node_client= ElectrumNodeClient::new(
        config.electrum_node_client().ok().expect("node missing"), true);

    let kc_sell = _keychain(2);
    let mut api_sell = BtcSwapApi::<_, _>::new(
        node_client.clone(), btc_node_client);
    let ctx_sell = context_sell(&kc_sell);
    let btc_amount_sats = (((_qty as f64 / 1_000_000_000 as f64) as f64) * ((_rate as f64 / 1000_000_000 as f64) as f64)) as u64;
    println!("_qty = {}", _qty);
    println!("_rate = {}", _rate);
    println!("btc amount is {}", btc_amount_sats);
    let (mut swap_sell, action) = api_sell
        .create_swap_offer(
            &kc_sell,
            &ctx_sell,
            None,
            _qty,
            btc_amount_sats,
            Currency::Btc,
            _btc_redeem.to_owned(),
        ).unwrap();

    let message = api_sell.message(&kc_sell, &swap_sell).unwrap();
    let res = publisher.post_take(&message, _address);

    let action = api_sell.message_sent(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
    assert_eq!(swap_sell.status, Status::Offered);
    assert_eq!(action, Action::ReceiveMessage);
    println!("In swap, I am done creating the offer. ");
    store_swap_deal(&swap_sell, _wallet.get_data_file_dir(), &swap_sell.id.to_string());

    Ok(())
}

pub fn process_offer<'a, T: ?Sized, C, K>(wallet: &mut T,
                                          from: &dyn crate::contacts::types::Address,
                                          message: Message,
                                          config: &Wallet713Config,
                                          publisher: &mut Publisher
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    let node_client = HTTPNodeClient::new(
        &config.mwc_node_uri(),
        config.mwc_node_secret(),
    );
    let btc_node_client= ElectrumNodeClient::new(
        config.electrum_node_client().ok().expect("node missing"), true);
    let mut api_buy = BtcSwapApi::<_, _>::new(
        node_client.clone(), btc_node_client);

    let kc_buy = _keychain(2);
    let ctx_buy = context_buy(&kc_buy);
    let (mut swap_buy, action) = api_buy.accept_swap_offer(&kc_buy,
                                                           &ctx_buy,
                                                           None,
                                                           message).unwrap();

    assert_eq!(swap_buy.status, Status::Offered);
    assert_eq!(action, Action::SendMessage(1));

    let accepted_message = api_buy.message(&kc_buy, &swap_buy).unwrap();

    let res = publisher.post_take(&accepted_message, from.get_stripped().as_str());
    if res.is_err() {
        println!("Error in post_take: {:?}", res);
    }
    let action = api_buy
        .message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
        .unwrap();

    let (address, btc_amount) = match action {
        Action::DepositSecondary {
            currency: _,
            amount,
            address,
        } => {
            (address, amount)
        }
        _ => panic!("Invalid action"),
    };
    assert_eq!(swap_buy.status, Status::Accepted);

    let address = Address::from_str(&address).unwrap();
    println!("Offer accepted! Send {} satoshis to {}", btc_amount, address);

    loop {
        let ten_seconds = time::Duration::from_millis(10000);
        thread::sleep(ten_seconds);
        let action = api_buy.required_action(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();
        if action == Action::SendMessage(2) {
            break;
        }
        println!("Still waiting! please send {} satoshis to {}", btc_amount, address);
    }
    println!("Successfully confirmed, now starting redeem process");

    let redeem_message = api_buy.message(&kc_buy, &swap_buy).unwrap();
    api_buy.message_sent(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();

    let res = publisher.post_take(&redeem_message, &from.get_stripped().as_str());
    if res.is_err() {
        println!("Error in post_take (redeem): {:?}", res);
    }

    Ok(())
}


pub fn process_accept_offer<'a, T: ?Sized, C, K>(wallet: &mut T,
                                          from: &dyn crate::contacts::types::Address,
                                          message: Message,
                                          config: &Wallet713Config,
                                          publisher: &mut Publisher,
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    let node_client = HTTPNodeClient::new(
        &config.mwc_node_uri(),
        config.mwc_node_secret(),
    );
    let btc_node_client= ElectrumNodeClient::new(
        config.electrum_node_client().ok().expect("node missing"), true);

    let kc_sell = _keychain(1);
    let mut api_sell = BtcSwapApi::<_, _>::new(
        node_client.clone(), btc_node_client);

    let ctx_sell = context_sell(&kc_sell);
    let mut swap_sell = get_swap_deal(wallet.get_data_file_dir(), &message.id.to_string()).unwrap();

    let action = api_sell.receive_message(&kc_sell, &mut swap_sell, &ctx_sell, message).unwrap();
    assert_eq!(action, Action::PublishTx);
    assert_eq!(swap_sell.status, Status::Accepted);
    println!("Received message for publishing txs!");

    let action = api_sell.publish_transaction(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();

    match action {
        Action::Confirmations {
            required: _,
            actual,
        } => assert_eq!(actual, 0),
        _ => panic!("Invalid action"),
    }
    println!("Successfully submitted!");

    Ok(())
}

pub fn process_init_redeem<'a, T: ?Sized, C, K>(wallet: &mut T,
                                       from: &dyn crate::contacts::types::Address,
                                       message: Message,
                                       config: &Wallet713Config,
                                       publisher: &mut Publisher
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    let node_client = HTTPNodeClient::new(
        &config.mwc_node_uri(),
        config.mwc_node_secret(),
    );
    let btc_node_client= ElectrumNodeClient::new(
        config.electrum_node_client().ok().expect("node missing"), true);
    let kc_sell = _keychain(1);
    let mut api_sell = BtcSwapApi::<_, _>::new(
        node_client.clone(), btc_node_client);

    let ctx_sell = context_sell(&kc_sell);
    let mut swap_sell = get_swap_deal(wallet.get_data_file_dir(), &message.id.to_string()).unwrap();

    loop {
        let action = api_sell.required_action(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
        println!("action={:?}", action);
        if action == Action::ReceiveMessage {
            break;
        }

        let ten_seconds = time::Duration::from_millis(10000);
        thread::sleep(ten_seconds);
    }

    let _action = api_sell.receive_message(&kc_sell, &mut swap_sell, &ctx_sell, message).unwrap();
    let signed_redeem_message = api_sell.message(&kc_sell,&swap_sell).unwrap();
    let res = publisher.post_take(&signed_redeem_message, &from.get_stripped());

    if res.is_err() {
        println!("Error: {:?}", res);
    } else {
        let _action = api_sell.message_sent(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
    }

    // Seller publishes BTX tx
    loop {
        let action = api_sell.required_action(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
        println!("action={:?}", action);
        if action == Action::PublishTxSecondary(Currency::Btc) {
            break;
        }

        let ten_seconds = time::Duration::from_millis(10000);
        thread::sleep(ten_seconds);
    }

    // Seller waits for BTC confirmations
    let action = api_sell.publish_secondary_transaction(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
    match action {
        Action::ConfirmationRedeemSecondary(_, _) => {}
        _ => panic!("Invalid action"),
    };

    // Seller completes
    let action = api_sell.required_action(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
    assert_eq!(action, Action::Complete);
    let action = api_sell.completed(&kc_sell, &mut swap_sell, &ctx_sell).unwrap();
    assert_eq!(action, Action::None);
    assert_eq!(swap_sell.status, Status::Completed);

    Ok(())
}

pub fn process_redeem<'a, T: ?Sized, C, K>(wallet: &mut T,
                                   from: &dyn crate::contacts::types::Address,
                                   message: Message,
                                   config: &Wallet713Config,
                                   publisher: &mut Publisher
) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: grinswap::Keychain + 'a,
{
    let node_client = HTTPNodeClient::new(
        &config.mwc_node_uri(),
        config.mwc_node_secret(),
    );
    let btc_node_client= ElectrumNodeClient::new(
        config.electrum_node_client().ok().expect("node missing"), true);
    let kc_buy = _keychain(2);
    let mut api_buy = BtcSwapApi::<_, _>::new(
        node_client.clone(), btc_node_client);

    let ctx_buy = context_sell(&kc_buy);
    let mut swap_buy = get_swap_deal(wallet.get_data_file_dir(), &message.id.to_string()).unwrap();

    loop {
        let action = api_buy.required_action(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();
        println!("action = {:?}", action);
        if action == Action::ReceiveMessage {
            break;
        }

        let ten_seconds = time::Duration::from_millis(10000);
        thread::sleep(ten_seconds);
    }

    let action = api_buy.receive_message(&kc_buy, &mut swap_buy, &ctx_buy, message).unwrap();
    assert_eq!(action, Action::PublishTx);
    assert_eq!(swap_buy.status, Status::Redeem);

    api_buy.publish_transaction(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();

    loop {
        let ten_seconds = time::Duration::from_millis(10000);
        thread::sleep(ten_seconds);

        let action = api_buy.required_action(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();
        println!("action = {:?}", action);

        if action == Action::Complete {
            break;
        }
    }

    println!("Buyer completes!");
    Ok(())
}

pub struct SwapProcessor {
    pub is_sell: bool,
    pub quantity: u64,
    pub rate: u64,
    pub btc_redeem: String,
}

impl SwapProcessor {
    pub fn new(is_seller: bool,
               qty: u64,
               secondary: u64,
               redeem_address: String) -> SwapProcessor {
        Self{is_sell: is_seller,
             quantity: qty,
             rate: secondary,
             btc_redeem: redeem_address.clone()
        }
    }

    pub fn process_swap_message<'a, T: ?Sized, C, K>(wallet: &mut T,
                                                     from: &dyn crate::contacts::types::Address,
                                                     message: Message,
                                                     config: &Wallet713Config,
                                                     publisher: &mut Publisher,
    ) -> Result<(), Error>
        where
            T: WalletBackend<'a, C, K>,
            C: NodeClient + 'a,
            K: grinswap::Keychain + 'a,
    {
        println!("Processing swap message!!!");

        let _res = match &message.inner {
            Update::Offer(_u) => process_offer(wallet, from, message, config, publisher),
            Update::AcceptOffer(_u) => process_accept_offer(wallet, from, message, config, publisher),
            Update::InitRedeem(_u) => process_init_redeem(wallet, from, message, config, publisher),
            Update::Redeem(_u) => process_redeem(wallet, from, message, config, publisher),
            _ => Err(ErrorKind::SwapMessageError.into()),
        }?;

        Ok(())
    }

    pub fn swap<'a, T: ?Sized, C, K>(
          wallet: &mut T,
          pair: &str,
          is_make: bool,
          is_buy: bool,
          rate: u64,
          qty: u64,
          address: Option<&str>,
          publisher: &mut MWCMQPublisher,
          btc_redeem: Option<&str>,
          config: &Wallet713Config
    ) -> Result<(), Error>
    where
        T: WalletBackend<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
        {
            println!("Starting the swap!");

            init_swap_backend(wallet.get_data_file_dir()).unwrap_or_else(|e| {
                error!("Unable to init swap_backend_storage {}", e);
            });

            let ctx = match btc_redeem {
                Some(btc_address) => SwapProcessor::new(is_buy, qty, rate,
                                                   btc_address.to_string()),
                None => SwapProcessor::new(is_buy, qty, rate, String::new())
            };

            let _res = if is_make && is_buy {
                make_buy_mwc(wallet, rate, qty, config, publisher)
            } else if is_make {
                match btc_redeem {
                    Some(redeem) => make_sell_mwc(wallet, rate, qty,
                                                  redeem, config, publisher),
                    None => Ok(())
                }
            } else if is_buy {
                match btc_redeem{
                    Some(redeem) => take_buy_mwc(wallet, rate, qty,
                                                 redeem, address.unwrap(), config, publisher),
                    None => Ok(())
                }
            } else {
                match btc_redeem {
                    Some(redeem) => take_sell_mwc(wallet, rate, qty,
                                                  redeem, address.unwrap(), config, publisher),
                    None => Ok(())
                }
            };

            return _res;
        }
}

