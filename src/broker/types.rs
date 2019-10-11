use crate::wallet::types::{Slate, TxProof};

use grin_keychain::ExtKeychain;
use wallet::types::node_client::HTTPNodeClient;
use common::config::Wallet713Config;
use common::Error;
use grinswap::Context;
use contacts::Address;
use grinswap::Message;

pub enum CloseReason {
    Normal,
    Abnormal(Error),
}

pub trait Publisher {
    fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error>;
    fn post_take(&self, message: &Message, to: &str) -> Result<(), Error>;
}

pub trait Subscriber {
    fn start(&mut self, handler: Box<dyn SubscriptionHandler + Send>, context_holder: &mut Box<dyn ContextHolderType + Send>) -> Result<(), Error>;
    fn stop(&mut self) -> bool;
    fn is_running(&self) -> bool;
}

pub trait ContextHolderType: Send {
    fn get_context(&mut self) -> Option<&Context>;
    fn set_context(&mut self, ctx: Context);
}

pub trait SubscriptionHandler: Send {
    fn on_open(&self);
    fn on_slate(&self, from: &dyn Address, slate: &mut Slate, proof: Option<&mut TxProof>, Option<Wallet713Config>);
    fn on_message(&mut self, from: &dyn Address, message: Message, Option<Wallet713Config>, &mut Box<dyn ContextHolderType + Send>);
    fn on_close(&self, result: CloseReason);
    fn on_dropped(&self);
    fn on_reestablished(&self);
}
