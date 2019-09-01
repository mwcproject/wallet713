extern crate reqwest;

use ws::{
    Error as WsError, ErrorKind as WsErrorKind,
};



use colored::Colorize;

use common::crypto::sign_challenge;
use common::crypto::Hex;
use regex::Regex;
use std::{thread, time};
use crate::wallet::types::{Slate, TxProof, TxProofErrorKind};
use std::time::Duration;
use std::io::Read;
use std::collections::HashMap;
use common::COLORED_PROMPT;
use common::config::Wallet713Config;
use common::crypto::SecretKey;
use common::message::EncryptedMessage;
use common::{Arc, ErrorKind, Mutex, Result};
use contacts::{Address, GrinboxAddress, MWCMQSAddress, DEFAULT_MWCMQS_PORT};

use super::types::{Publisher, Subscriber, SubscriptionHandler};

const TIMEOUT_ERROR_REGEX: &str = r"timed out";

#[derive(Clone)]
pub struct MWCMQPublisher {
    address: MWCMQSAddress,
    broker: MWCMQSBroker,
    secret_key: SecretKey,
    config: Wallet713Config,
}

impl MWCMQPublisher {
    pub fn new(
        address: &MWCMQSAddress,
        secret_key: &SecretKey,
        config: &Wallet713Config,
    ) -> Result<Self> {
        Ok(Self {
            address: address.clone(),
            broker: MWCMQSBroker::new(config.clone())?,
            secret_key: secret_key.clone(),
            config: config.clone(),
        })
    }
}

impl Publisher for MWCMQPublisher {
    fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<()> {
        let to = MWCMQSAddress::from_str(&to.to_string())?;
        self.broker.post_slate(slate, &to, &self.address, &self.secret_key)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct MWCMQSubscriber {
    address: MWCMQSAddress,
    broker: MWCMQSBroker,
    secret_key: SecretKey,
    config: Wallet713Config,
}

impl MWCMQSubscriber {
    pub fn new(publisher: &MWCMQPublisher) -> Result<Self> {
        Ok(Self {
            address: publisher.address.clone(),
            broker: publisher.broker.clone(),
            secret_key: publisher.secret_key.clone(),
            config: publisher.config.clone(),
        })
    }
}

impl Subscriber for MWCMQSubscriber {
    fn start(&mut self, handler: Box<dyn SubscriptionHandler + Send>) -> Result<()> {
        self.broker
            .subscribe(&self.address, &self.secret_key, handler, self.config.clone());
        Ok(())
    }

    fn stop(&self) {
        self.broker.stop();


        let client = reqwest::Client::builder()
                         .timeout(Duration::from_secs(60))
                         .build().unwrap();



        let mut params = HashMap::new();
        params.insert("mapmessage", "nil");
        let _response = client.post(&format!("https://{}:{}/sender?address={}",
                                              self.config.mwcmqs_domain(),
                                              self.config.mwcmqs_port(),
                        str::replace(&self.address.stripped(), "@", "%40")))
                        .form(&params)
                        .send();

    }

    fn is_running(&self) -> bool {
        self.broker.is_running()
    }
}

#[derive(Clone)]
struct MWCMQSBroker {
    inner: Arc<Mutex<Option<()>>>,
    config: Wallet713Config,
}

impl MWCMQSBroker {
    fn new(config: Wallet713Config) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(None)),
            config: config,
        })
    }

    fn post_slate(
        &self,
        slate: &Slate,
        to: &MWCMQSAddress,
        from: &MWCMQSAddress,
        secret_key: &SecretKey,
    ) -> Result<()> {

        if !self.is_running() {
            return Err(ErrorKind::ClosedListener("mwcmqs".to_string()).into());
        }
        let pkey = to.public_key()?;
        let domain = &to.domain;
        let port = to.port;
        let skey = secret_key.clone();

        let to_str = str::replace(&format!("{:?}@{}:{}",
                     &to.public_key,
                     domain,
                     port.unwrap_or(DEFAULT_MWCMQS_PORT)), "\"", "");
        let message = EncryptedMessage::new(
            serde_json::to_string(&slate)?,
            &GrinboxAddress::from_str(&to_str)?,
            &pkey,
            &skey,
        )
            .map_err(|_| {
                WsError::new(WsErrorKind::Protocol, "could not encrypt slate!")
            })?;

        let message_ser = &serde_json::to_string(&message)?;
        let mut challenge = String::new();
        challenge.push_str(&message_ser);
        let signature = sign_challenge(&challenge, secret_key);
        let signature = signature.unwrap().to_hex();

        let client = reqwest::Client::builder()
                         .timeout(Duration::from_secs(60))
                         .build()?;

        let mser: &str = &message_ser;
        let fromstripped = from.stripped();

        let mut params = HashMap::new();
        params.insert("mapmessage", mser);
        params.insert("from", &fromstripped);
        params.insert("signature", &signature);

        let response = client.post(&format!("https://{}:{}/sender?address={}",
                                              self.config.mwcmqs_domain(),
                                              self.config.mwcmqs_port(),
                                              &str::replace(&to.stripped(), "@", "%40")))
                        .form(&params)
                        .send();

        if !response.is_ok() {
            return Err(ErrorKind::InvalidRespose("mwcmqs connection error".to_string()).into());
        } else {
            let mut response = response.unwrap();
            let mut resp_str = "".to_string();
            let read_resp = response.read_to_string(&mut resp_str);

            if !read_resp.is_ok() {
                return Err(ErrorKind::InvalidRespose("mwcmqs i/o error".to_string()).into());
            }
            else {
                let data: Vec<&str> = resp_str.split(" ").collect();
                if data.len() <= 1 {
                    return Err(ErrorKind::InvalidRespose("mwcmqs".to_string()).into());
                } else {
                    let last_seen = data[1].parse::<i64>();
                    if !last_seen.is_ok() {
                        return Err(ErrorKind::InvalidRespose("mwcmqs".to_string()).into());
                    } else {
                        let last_seen = last_seen.unwrap();
                        if last_seen > 10000000000 {
                            println!("\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the slate.",
                                  to.stripped().bright_green());
                        }
                        else if last_seen > 150000 {
                            let seconds = last_seen / 1000;
                            println!("\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the slate.",
                                  to.stripped().bright_green(), seconds);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn print_error(&mut self, messages: Vec<&str>, error: &str, code: i16)
    {
        println!("{}: messages=[{:?}] produced error: {} (code={})",
                 "ERROR".bright_red(),
                 messages,
                 error,
                 code);
    }

    fn subscribe(
        &mut self,
        address: &MWCMQSAddress,
        secret_key: &SecretKey,
        handler: Box<dyn SubscriptionHandler + Send>,
        config: Wallet713Config,
    ) -> () {
        let handler = Arc::new(Mutex::new(handler));
        {
             let mut guard = self.inner.lock();
             *guard = Some(());
        }

        let secret_key = secret_key.clone();
        let cloned_address = address.clone();
        let cloned_inner = self.inner.clone();
        let mut count = 0;
        let mut connected = false;
        let mut isnginxerror = false;
        let mut delcount = 0;
        let mut is_in_warning = false;
        loop {
            count = count + 1;
            let cloned_cloned_address = cloned_address.clone();
            {
                let mut guard = cloned_inner.lock();
                if guard.is_none() { break;}
                *guard = Some(());
            }

            let is_stopped = cloned_inner.lock().is_none();
            if is_stopped { break; }

            let secs = if !connected { 2 } else { 120 };
            let cl = reqwest::Client::builder()
                         .timeout(Duration::from_secs(secs))
                         .build();
            let client = if cl.is_ok() {
                cl.unwrap()
            } else {
                self.print_error([].to_vec(), "couldn't instantiate client", -101);
                continue;
            };

            let mut first_response = true;
            let resp_result = client.get(&format!("https://{}:{}/listener?address={}&delcount={}",
                                        config.mwcmqs_domain(),
                                        config.mwcmqs_port(),
                                        cloned_cloned_address.stripped(),
                                        delcount)).send();
            if !resp_result.is_ok() {
                let err_message = format!("{:?}", resp_result);
                let re = Regex::new(TIMEOUT_ERROR_REGEX).unwrap();
                let captures = re.captures(&err_message);
                if captures.is_none() {
                    // This was not a timeout. Sleep first.
                    if connected {
                        is_in_warning = true;
                        println!("\n{}: mwcmqs listener [{}] lost connection. Will try to restore in the background.",
                                 "WARNING".bright_yellow(),
                                 cloned_cloned_address.stripped().bright_green());
                    }


                    let second = time::Duration::from_millis(5000);
                    thread::sleep(second);

                    connected = false;
                }
                else if count == 1 {
                    delcount = 0;
                    println!("\nmwcmqs listener started for [{}]",
                             cloned_cloned_address.stripped().bright_green());
                    print!("{}", COLORED_PROMPT);
                    connected = true;
                } else {
                    delcount = 0;
                    if !connected {
                        if is_in_warning {
                            println!("{}: mwcmqs listener [{}] reestablished connection. [1]",
                                "INFO".bright_blue(),
                                cloned_cloned_address.stripped().bright_green());
                            is_in_warning = false;
                        }
                    }
                    connected = true;
                }
            }
            else
            {
                if count == 1 {
                    println!("\nmwcmqs listener started for: [{}]",
                             cloned_cloned_address.stripped().bright_green());
                    print!("{}", COLORED_PROMPT);
                } else if !connected && !isnginxerror {
                    if is_in_warning {
                        println!("{}: listener [{}] reestablished connection. [2]",
                             "INFO".bright_blue(),
                             cloned_cloned_address.stripped().bright_green());
                        is_in_warning = false;
                    }
                    connected = true;
                } else if !isnginxerror {
                    connected = true;
                }

                let mut resp = resp_result.unwrap();
                let mut resp_str = "".to_string();
                let read_resp = resp.read_to_string(&mut resp_str);
                if !read_resp.is_ok() {
                    // read error occured. Sleep and try again in 5 seconds
                    println!("io error occured while trying to connect to {}. Will sleep for 5 second and will reconnect.",
                             &format!("https://{}:{}", config.mwcmqs_domain(), config.mwcmqs_port()));
                    println!("Error: {:?}", read_resp);
                    let second = time::Duration::from_millis(5000);
                    thread::sleep(second);
                    continue;
                }
                let msgvec: Vec<&str> = if resp_str.starts_with("messagelist: ") {
                    let mut ret: Vec<&str> = Vec::new();
                    let lines: Vec<&str> = resp_str.split("\n").collect();
                    for i in 1..lines.len() {
                        let params: Vec<&str> = lines[i].split(" ").collect();
                        if params.len() >= 2 {
                            ret.push(&params[1]);
                        }
                    }
                    ret
                } else {
                    vec![&resp_str]
                };

                for itt in 0..msgvec.len() {
                    if msgvec[itt] == "message: mapmessage=nil\n" || msgvec[itt] == "mapmessage=nil" {
                        if first_response {
                            delcount = 1;
                            first_response = false;
                        } else {
                            delcount = delcount + 1;
                        }
                        // this is our exit message. Just ignore.
                        continue;
                    }
                    let split = msgvec[itt].split(" ");
                    let vec: Vec<&str> = split.collect();
                    let splitx = if vec.len() == 1 {
                        vec[0].split("&")
                    }
                    else if vec.len() >= 2 {
                        vec[1].split("&")
                    } else {
                        self.print_error(msgvec.clone(), "too many spaced messages", -1);
                        continue;
                    };

                    let splitxvec: Vec<&str> = splitx.collect();
                    let splitxveclen = splitxvec.len();
                    if splitxveclen != 3 {
                        if msgvec[itt].find("502 Bad Gateway").is_some() {
                            // this is common for nginx to return if the server is down.
                            // so we don't print. We also add a small sleep here.
                            connected = false;
                            if !isnginxerror {
                                 is_in_warning = true;
                                 println!("\n{}: mwcmqs listener [{}] lost connection. Will try to restore in the background.",
                                 "WARNING".bright_yellow(),
                                 cloned_cloned_address.stripped().bright_green());
                            }
                            isnginxerror = true;
                            let second = time::Duration::from_millis(5000);
                            thread::sleep(second);
                        } else {
                            self.print_error(msgvec.clone(),
                                             "splitxveclen != 3",
                                             -2);
                        }
                        continue;
                    } else if isnginxerror {
                        isnginxerror = false;
                        connected = true;
                    }

                    let mut from = "".to_string();
                    for i in 0..3 {
                        if splitxvec[i].starts_with("from=") {
                            let vec: Vec<&str> = splitxvec[i].split("=").collect();
                            if vec.len() <= 1 {
                                self.print_error(msgvec.clone(),
                                         "vec.len <= 1",
                                         -3);
                                continue;
                            }
                            from = str::replace(&vec[1].to_string().trim().to_string(), "%40", "@");
                        }
                    }
                    let mut signature = "".to_string();
                    for i in 0..3 {
                        if splitxvec[i].starts_with("signature=") {
                            let vec: Vec<&str> = splitxvec[i].split("=").collect();
                            if vec.len() <= 1 {
                                self.print_error(msgvec.clone(),
                                         "vec.len <= 1",
                                         -4);
                                continue;
                            }
                            signature = vec[1].to_string().trim().to_string();
                        }
                    }
                    for i in 0..3 {
                        if splitxvec[i].starts_with("mapmessage=") {


                            let split2 = splitxvec[i].split("=");
                            let vec2: Vec<&str> = split2.collect();
                            if vec2.len() <= 1 {
                                self.print_error(msgvec.clone(),
                                         "vec2.len <= 1",
                                         -5);
                                continue;
                            }
                            let r1 = str::replace(vec2[1], "%22", "\"");
                            let r2 = str::replace(&r1, "%7B", "{");
                            let r3 = str::replace(&r2, "%7D", "}");
                            let r4 = str::replace(&r3, "%3A", ":");
                            let r5 = str::replace(&r4, "%2C", ",");
                            let r5 = r5.trim().to_string();

                            if first_response {
                                delcount = 1;
                                first_response = false;
                            } else {
                                delcount = delcount + 1;
                            }

                            let (mut slate, mut tx_proof) = match TxProof::from_response(
                                        from.clone(),
                                        r5.clone(),
                                        "".to_string(),
                                        signature.clone(),
                                        &secret_key,
                                        Some(&config.get_grinbox_address().unwrap()),
                            ) {
                                Ok(x) => x,
                                Err(TxProofErrorKind::ParseAddress) => {
                                    cli_message!("could not parse address!");
                                    continue;
                                }
                                Err(TxProofErrorKind::ParsePublicKey) => {
                                    cli_message!("could not parse public key!");
                                    continue;
                                }
                                Err(TxProofErrorKind::ParseSignature) => {
                                    cli_message!("could not parse signature!");
                                    continue;
                                }
                                Err(TxProofErrorKind::VerifySignature) => {
                                    cli_message!("invalid slate signature!");
                                    continue;
                                }
                                Err(TxProofErrorKind::ParseEncryptedMessage) => {
                                    cli_message!("could not parse encrypted slate!");
                                    continue;
                                }
                                Err(TxProofErrorKind::VerifyDestination) => {
                                    cli_message!("could not verify destination!");
                                    continue;
                                }
                                Err(TxProofErrorKind::DecryptionKey) => {
                                    cli_message!("could not determine decryption key!");
                                    continue;
                                }
                                Err(TxProofErrorKind::DecryptMessage) => {
                                    cli_message!("could not decrypt slate!");
                                    continue;
                                }
                                Err(TxProofErrorKind::ParseSlate) => {
                                    cli_message!("could not parse decrypted slate!");
                                    continue;
                                }
                            };

                            let from = MWCMQSAddress::from_str(&from);
                            let from = if !from.is_ok() {
                                self.print_error(msgvec.clone(),
                                         "error parsing from",
                                         -12);
                                continue;
                            } else {
                                from.unwrap()
                            };

                            handler.lock().on_slate(
                                    &from,
                                    &mut slate,
                                    Some(&mut tx_proof),
                                    Some(self.config.clone()));
                            break;
                        }
                    }
                }
            }
        }

        println!("\nmwcmqs listener [{}] stopped", address.stripped().bright_green());
        let mut guard = cloned_inner.lock();
        *guard = None;
    }

    fn stop(&self) {
        let mut guard = self.inner.lock();
        if let Some(ref _sender) = *guard {
        }
        *guard = None;
    }

    fn is_running(&self) -> bool {
        let guard = self.inner.lock();
        guard.is_some()
    }
}

