extern crate reqwest;

use ws::{
    Error as WsError, ErrorKind as WsErrorKind,
};



use crate::common::crypto::from_hex;
use colored::Colorize;
use grin_util::secp::Secp256k1;
use ring::{digest, pbkdf2};

use ring::aead;
use regex::Regex;
use std::{thread, time};
use crate::wallet::types::Slate;
use std::time::Duration;
use serde_json::Value;
use std::io::Read;
use std::collections::HashMap;
use common::config::Wallet713Config;
use common::crypto::{PublicKey, SecretKey};
use common::message::EncryptedMessage;
use common::{Arc, ErrorKind, Mutex, Result};
use contacts::{Address, GrinboxAddress, MWCMQSAddress};

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
            .subscribe(&self.address, &self.secret_key, handler, self.config.clone())?;
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
                                              self.address.stripped()))
                        .form(&params)
                        .send()
                        .expect("Failed to send request");
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
        let skey = secret_key.clone();

        let to_str = to.stripped();
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

        let client = reqwest::Client::builder()
                         .timeout(Duration::from_secs(60))
                         .build()?;

        let mser: &str = &message_ser;
        let fromstripped = from.stripped();


        let mut params = HashMap::new();
        params.insert("mapmessage", mser);
        params.insert("from", &fromstripped);
        let response = client.post(&format!("https://{}:{}/sender?address={}",
                                              self.config.mwcmqs_domain(),
                                              self.config.mwcmqs_port(),
                                              to.stripped()))
                        .form(&params)
                        .send();

        if !response.is_ok() {
            println!("ERROR: could not connect to mwcmqs server");
        } else {
            let mut response = response.unwrap();
            let mut resp_str = "".to_string();
            let read_resp = response.read_to_string(&mut resp_str);

            if !read_resp.is_ok() {
                println!("ERROR: Could not send slate due to i/o error");
            }
            else {
                let data: Vec<&str> = resp_str.split(" ").collect();
                if data.len() <= 1 {
                    println!("Invalid response from send");
                } else {
                    let last_seen = data[1].parse::<i64>();
                    if !last_seen.is_ok() {
                        println!("Error: could not parse int returned");
                    } else {
                        let last_seen = last_seen.unwrap();
                        if last_seen > 10000000000 {
                            println!("WARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the slate.",
                                  to.stripped().bright_green());
                        }
                        else if last_seen > 150000 {
                            let seconds = last_seen / 1000;
                            println!("WARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the slate.",
                                  to.stripped().bright_green(), seconds);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn subscribe(
        &mut self,
        address: &MWCMQSAddress,
        secret_key: &SecretKey,
        handler: Box<dyn SubscriptionHandler + Send>,
        config: Wallet713Config,
    ) -> Result<()> {
        let handler = Arc::new(Mutex::new(handler));
        {
             let mut guard = self.inner.lock();
             *guard = Some(());
        }

        let secret_key = secret_key.clone();
        let cloned_address = address.clone();
        let cloned_inner = self.inner.clone();
        let mut count = 0;
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

            let client = if count == 1 {
                reqwest::Client::builder()
                         .timeout(Duration::from_secs(1))
                         .build()?
            } else {
                reqwest::Client::builder()
                         .timeout(Duration::from_secs(120))
                         .build()?
            };
         
            let resp_result = client.get(&format!("https://{}:{}/listener?address={}",
                                        config.mwcmqs_domain(),
                                        config.mwcmqs_port(),
                                        cloned_cloned_address.stripped())).send();
            if !resp_result.is_ok() {
                let err_message = format!("{:?}", resp_result);
                let re = Regex::new(TIMEOUT_ERROR_REGEX)?;
                let captures = re.captures(&err_message);
                if captures.is_none() {
                    // This was not a timeout. Sleep first.
                    println!("io error occured while trying to connect to {}. Will sleep for 5 second and will reconnect.",
                             &format!("https://{}:{}", config.mwcmqs_domain(), config.mwcmqs_port()));
                    println!("Error: {}", err_message);
                    let second = time::Duration::from_millis(5000);
                    thread::sleep(second);
                }
                if count == 1 {
                    println!("mwcmqs listener started for [{}]",
                             cloned_cloned_address.stripped().bright_green());
                }
            }
            else
            {
                if count == 1 {
                    println!("mwcmqs listener started for: [{}]",
                             cloned_cloned_address.stripped().bright_green());
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
                    let split = msgvec[itt].split(" ");
                    let vec: Vec<&str> = split.collect();
                    let splitx = if vec.len() == 1 {
                        vec[0].split("&")
                    }
                    else if vec.len() >= 2 {
                        vec[1].split("&")
                    } else {
                        continue;
                    };

                    let splitxvec: Vec<&str> = splitx.collect();
        
                    for i in 0..splitxvec.len() {
                        if splitxvec[i].starts_with("mapmessage=") {

                            let from =
                                if i == 0 {
                                    if splitxvec.len() <= 1 { continue; }
                                    let tmp = splitxvec[1].split("=");
                                    let vecs:Vec<&str> = tmp.collect();
                                    if vecs.len() <= 1 { continue; }
                                    vecs[1].trim()
                                } else {
                                    let tmp = splitxvec[0].split("=");
                                    let vecs:Vec<&str> = tmp.collect();
                                    if vecs.len() <= 1 { continue; }
                                    vecs[1].trim()
                                };

                            let split2 = splitxvec[i].split("=");
                            let vec2: Vec<&str> = split2.collect();
                            if vec2.len() <= 1 { continue; }
	                    let r1 = str::replace(vec2[1], "%22", "\"");
                            let r2 = str::replace(&r1, "%7B", "{");
                            let r3 = str::replace(&r2, "%7D", "}");
                            let r4 = str::replace(&r3, "%3A", ":");
                            let r5 = str::replace(&r4, "%2C", ",");
                            let v = serde_json::from_str(&r5);
                            let v: Value = if !v.is_ok() {
                                continue;
                            } else {
                                v.unwrap()
                            };
                            let salt = v.get("salt");
                            let salt = if salt.is_some() {
                                str::replace(&salt.unwrap().to_string(), "\"", "")
                            } else {
                                continue;
                            };
 
                            let nonce = v.get("nonce");
                            let nonce = if nonce.is_some() {
                                str::replace(&nonce.unwrap().to_string(), "\"", "")
                            } else {
                                continue;
                            };

                            let encrypted_message = v.get("encrypted_message");
                            let encrypted_message = if encrypted_message.is_some() {
                                str::replace(&encrypted_message.unwrap().to_string(), "\"", "")
                            } else {
                                continue;
                            };

                            let encrypted =
                                from_hex(encrypted_message.clone()).map_err(|_| ErrorKind::Decryption);
                            let mut encrypted = if !encrypted.is_ok() {
                                continue;
                            } else {
                                encrypted.unwrap()
                            };

                            let nonce_x = from_hex(nonce).map_err(|_| ErrorKind::Decryption);
                            let nonce_x = if !nonce_x.is_ok() {
                                continue;
                            } else {
                                nonce_x.unwrap()
                            };

                            let from = MWCMQSAddress::from_str(from);
                            let from = if !from.is_ok() {
                                continue;
                            } else {
                                from.unwrap()
                            };

                            let pubkey = from.public_key();
                            let pubkey = if !pubkey.is_ok() {
                                continue;
                            } else {
                                pubkey.unwrap()
                            };

                            let skey = self.key(salt, &pubkey, &secret_key);
                            let skey = if !skey.is_ok() {
                                continue;
                            } else {
                                skey.unwrap()
                            };

                            let opening_key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &skey)
                                .map_err(|_| ErrorKind::Decryption);
                            let opening_key = if !opening_key.is_ok() {
                                continue;
                            } else {
                                 opening_key.unwrap()
                            };

                            let decrypted_data =
                                aead::open_in_place(&opening_key, &nonce_x, &[], 0, &mut encrypted)
                                .map_err(|_| ErrorKind::Decryption);
                            let decrypted_data = if !decrypted_data.is_ok() {
                                continue;
                            } else {
                                decrypted_data.unwrap()
                            };

                            let decr = String::from_utf8(decrypted_data.to_vec());

                            let decr = if !decr.is_ok() {
                                continue;
                            } else {
                                decr.unwrap()
                            };

                            let slate = Slate::deserialize_upgrade(&decr);
                            let mut slate = if !slate.is_ok() {
                                continue;
                            } else {
                                slate.unwrap()
                            };

                            handler.lock().on_slate(
                                    &from,
                                    &mut slate,
                                    None,
                                    Some(self.config.clone()));
                            break;
                        }
                    }
                }
            }
        }

        println!("mwcmqs listener [{}] stopped", address.stripped().bright_green());
        let mut guard = cloned_inner.lock();
        *guard = None;
        Ok(())
    }

    fn key(&self, salt: String, sender_public_key: &PublicKey, secret_key: &SecretKey) -> Result<[u8; 32]> {
        let salt = from_hex(salt.clone()).map_err(|_| ErrorKind::Decryption)?;

        let secp = Secp256k1::new();
        let mut common_secret = sender_public_key.clone();
        common_secret
            .mul_assign(&secp, secret_key)
            .map_err(|_| ErrorKind::Decryption)?;
        let common_secret_ser = common_secret.serialize_vec(&secp, true);
        let common_secret_slice = &common_secret_ser[1..33];

        let mut key = [0; 32];
        pbkdf2::derive(&digest::SHA512, 100, &salt, common_secret_slice, &mut key);

        Ok(key)
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

