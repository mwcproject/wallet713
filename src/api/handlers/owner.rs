use failure::Error;
use grin_core::core::amount_to_hr_string;
use colored::Colorize;
use std::io::Write;
use url::Url;
use grin_api::client::post;
use grin_wallet_libwallet::{VersionedSlate, SlateVersion, TxLogEntry};
use std::fs::File;
use std::clone::Clone;
use serde_json::Value;
use gotham::handler::{HandlerFuture, IntoHandlerError, IntoResponse};
use gotham::helpers::http::response::create_empty_response;
use gotham::helpers::http::response::create_response;
use gotham::state::{FromState, State};
use hyper::body::Chunk;
use hyper::{Body, Response, StatusCode};
use std::str::FromStr;
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::router::{
    trace_create_response, trace_state, trace_state_and_body, WalletContainer,
};
use crate::broker::Publisher;
use crate::common::ErrorKind;
use crate::contacts::{Address, MWCMQSAddress, KeybaseAddress};
use grin_wallet_libwallet::Slate;

#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SlateResult {
    Ok: Slate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SlateResp {
    id: u32,
    jsonrpc: String,
    result: SlateResult,
}

pub fn retrieve_outputs(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_retrieve_outputs ) )
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct RetrieveOutputsQueryParams {
    refresh: Option<bool>,
    show_spent: Option<bool>,
    tx_id: Option<u32>,
}

fn handle_retrieve_outputs(state: &State, _body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state(state);
    let &RetrieveOutputsQueryParams {
        refresh,
        show_spent,
        tx_id,
    } = RetrieveOutputsQueryParams::borrow_from(&state);
    let wallet = WalletContainer::borrow_from(&state).lock()?;

    let mut tx : Option<TxLogEntry> = None;

    if tx_id.is_some() {
        let (_, mut txs) = wallet.retrieve_txs(false,
                                           tx_id, None)?;
        if !txs.is_empty() {
            tx = Some(txs.remove(0));
        }
    }

    let response =
        wallet.retrieve_outputs(show_spent.unwrap_or(false), refresh.unwrap_or(true), tx.as_ref())?;

    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_string(&response)?,
    ))
}

pub fn retrieve_txs(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_retrieve_txs ) )
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct RetrieveTransactionsQueryParams {
    refresh: Option<bool>,
    id: Option<u32>,
    tx_id: Option<String>,
}

pub fn handle_retrieve_txs(state: &State, _body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state(state);
    let &RetrieveTransactionsQueryParams {
        refresh,
        id,
        ref tx_id,
    } = RetrieveTransactionsQueryParams::borrow_from(&state);
    let wallet = WalletContainer::borrow_from(&state).lock()?;
    let response = wallet.retrieve_txs(
        refresh.unwrap_or(true),
        id,
        tx_id
            .clone()
            .map(|x| Uuid::from_str(&x).unwrap_or(Uuid::default())),
    )?;
    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_string(&response)?,
    ))
}

pub fn retrieve_stored_tx(state: State) -> (State, Response<Body>) {
    let res = match handle_retrieve_stored_tx(&state) {
        Ok(res) => res,
        Err(e) => ApiError::new(e).into_handler_error().into_response(&state),
    };
    (state, res)
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct RetrieveStoredTransactionQueryParams {
    id: u32,
}

fn handle_retrieve_stored_tx(state: &State) -> Result<Response<Body>, Error> {
    trace_state(state);
    let &RetrieveStoredTransactionQueryParams { id } =
        RetrieveStoredTransactionQueryParams::borrow_from(&state);
    let wallet = WalletContainer::borrow_from(&state).lock()?;
    let (_, txs) = wallet.retrieve_txs(true, Some(id), None)?;
    if txs.len() != 1 {
        return Err(ErrorKind::TransactionModelNotFound.into());
    }

    if txs[0].tx_slate_id.is_none() {
        return Err(ErrorKind::TransactionModelNotFound.into());
    }

    let stored_tx = wallet.get_stored_tx(&txs[0].tx_slate_id.unwrap().to_string())?;
    let response = (txs[0].confirmed, Some(stored_tx));
    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_string(&response)?,
    ))
}

pub fn node_height(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_node_height ) )
}

pub fn handle_node_height(state: &State, _body: &Chunk) -> Result<Response<Body>, Error>  {
    let wallet = WalletContainer::borrow_from(&state).lock()?;

    let res : Response<Body> = match wallet.node_height() {
        Ok((height, success)) => {
            if success {
                // The only Success respond
                create_response(&state, StatusCode::OK, mime::TEXT_PLAIN, format!("{{\"height\": {} }}", height))
            } else {
                create_response(&state, StatusCode::OK, mime::TEXT_PLAIN, "{\"error\": \"could not connect to node\"}")
            }
        },
        Err(_) => {
            create_response(&state, StatusCode::OK, mime::TEXT_PLAIN, "{\"error\": \"could not connect to node\"}")
        },
    };

    Ok(res)
}

pub fn retrieve_summary_info(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handler_retrieve_summary_info ) )
}

pub fn handler_retrieve_summary_info(state: &State, _body: &Chunk) -> Result<Response<Body>, Error> {
    let wallet = WalletContainer::borrow_from(&state).lock()?;

    let sum_info = wallet.retrieve_summary_info(true, 10)?;
    let response = serde_json::to_string(&sum_info)?;

    let res = trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        response
    );
    Ok(res)
}

pub fn finalize_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_finalize_tx ) )
}

pub fn handle_finalize_tx(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state_and_body(state, body);
    let mut slate = Slate::deserialize_upgrade(&String::from_utf8(body.to_vec())?)?;
    let container = WalletContainer::borrow_from(&state);
    let wallet = container.lock()?;

    wallet.finalize_slate(&mut slate, None, false)?;

    Ok(create_empty_response(&state, StatusCode::OK))
}

pub fn cancel_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handler_cancel_tx ) )
}

pub fn handler_cancel_tx(state: &State, _body: &Chunk) -> Result<Response<Body>, Error> {

    let wallet = WalletContainer::borrow_from(&state).lock()?;

    let &CancelTransactionQueryParams { id } = CancelTransactionQueryParams::borrow_from(&state);

    let response = wallet.cancel(id);

    let ret =
        if response.is_err() {
            let full = format!("error = {:?}", response);
            // Transaction {} doesn't exist
            if full.contains("Transaction ") && full.contains(" doesn't exist") {
                format!("{{\"error\": \"TransactionDoesntExist\"}}")
            }
            // Transaction {} cannot be cancelled
            else if full.contains("Transaction ") && full.contains(" cannot be cancelled") {
                format!("{{\"error\": \"TransactionNotCancellable\"}}")
            } else {
                println!("Unknown error = {:?}", response);
                format!("{{\"error\": \"Unknown\"}}")
            }
        } else {
            format!("{{\"success\": true}}")
        };


    let res = trace_create_response(
                &state,
                StatusCode::OK,
                mime::APPLICATION_JSON,
                ret
            );

    Ok(res)
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct CancelTransactionQueryParams {
    id: u32,
}

pub fn post_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_post_tx ) )
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct PostTransactionQueryParams {
    fluff: Option<bool>,
}

pub fn handle_post_tx(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state_and_body(state, body);
    let slate = Slate::deserialize_upgrade(&String::from_utf8(body.to_vec())?)?;
    let &PostTransactionQueryParams { fluff } = PostTransactionQueryParams::borrow_from(&state);
    let container = WalletContainer::borrow_from(&state);
    let wallet = container.lock()?;
    wallet.post_tx(&slate.tx, fluff.unwrap_or(false))?;
    Ok(create_empty_response(&state, StatusCode::OK))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum IssueSendMethod {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "mwcmq")]
    Grinbox,
    #[serde(rename = "keybase")]
    Keybase,
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "file")]
    File,
    #[serde(rename = "mwcmqs")]
    MWCMQS,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IssueSendBody {
    method: IssueSendMethod,
    dest: Option<String>,
    amount: u64,
    minimum_confirmations: u64,
    max_outputs: u32,
    num_change_outputs: u32,
    selection_strategy_is_use_all: bool,
    message: Option<String>,
    version: Option<u16>,
}

pub fn issue_send_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_issue_send_tx ) )
}

pub fn handle_issue_send_tx(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    let container = WalletContainer::borrow_from(state);
    let res = process_handle_issue_send_tx(&container, body);

    let res_string = if res.is_ok() {
        res.unwrap()
    } else {
        println!("Error: {:?}", res);
        "{\"error\": \"Could not process send due to problem. See stdout for details.\"}".to_string()
    };


    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        res_string
    ))
}

pub fn process_handle_issue_send_tx(container: &WalletContainer, body: &Chunk) -> Result<String, Error> {
    let body: Result<IssueSendBody, serde_json::Error> = serde_json::from_slice(&body);
    if body.is_ok() {
        let body = body.unwrap();
        let selection_strategy = match body.selection_strategy_is_use_all {
            true => "all",
            false => "",
        };
        let wallet = &container.lock().unwrap();
        let res = match body.method {
            IssueSendMethod::MWCMQS => {
                if !body.dest.is_some() {
                    "{\"error\": \"dest was not specified.\"}".to_string()
                }
                else {
                    let address = MWCMQSAddress::from_str(body.dest.unwrap().as_str());

                    if address.is_ok() {
                        let address = address.unwrap();

                        let publisher = container.mwcmqs_publisher();
                        if publisher.is_ok() {
                            let publisher = publisher.unwrap();

                            let slate = wallet.initiate_send_tx(
                                Some(address.to_string()),
                                body.amount,
                                body.minimum_confirmations,
                                selection_strategy,
                                body.num_change_outputs,
                                body.max_outputs,
                                body.message,
                                None,
                                body.version,
                                1,
                                &None,
                            );

                            if slate.is_ok() {
                                let slate = slate.unwrap();
                                let res = publisher.post_slate(&slate, &address);
                                if res.is_ok() {
                                    wallet.tx_lock_outputs(&slate, Some(address.to_string()), 0)?;
                                    let versioned_slate = VersionedSlate::into_version(slate, SlateVersion::V2);
                                    serde_json::to_string(&versioned_slate)?
                                } else {
                                     println!("Error: {:?}", res);
                                     "{\"error\": \"An error occurred while posting slate.\"}".to_string()
                                }
                            } else {
                                println!("Error: {:?}", slate);
                                "{\"error\": \"An error occurred while generating slate.\"}".to_string()
                            }
                        } else {
                            "{\"error\": \"An error occurred sending to a mwcmqs address. Note: mwcmqs must be configured on startup to use with the API.\"}".to_string()
                        }
                    }
                    else {
                        println!("Error: {:?}", address);
                        "{\"error\": \"An error occurred while parsing mwcmqs address.\"}".to_string()
                    }
                }
            }
            IssueSendMethod::Keybase => {
                if !body.dest.is_some() {
                    "{\"error\": \"dest was not specified.\"}".to_string()
                }
                else {
                    let address = KeybaseAddress::from_str(
                        body.dest.unwrap().as_str()
                    );
                    if address.is_ok() {
                        let address = address.unwrap();
                        let publisher = container.keybase_publisher();
                        if publisher.is_ok() {
                            let publisher = publisher.unwrap();
                            let slate = wallet.initiate_send_tx(
                                Some(address.to_string()),
                                body.amount,
                                body.minimum_confirmations,
                                selection_strategy,
                                body.num_change_outputs,
                                body.max_outputs,
                                body.message,
                                None,
                                body.version,
                                1,
                                &None,
                            );

                            if slate.is_ok() {
                                let slate = slate.unwrap();
                                let res = publisher.post_slate(&slate, &address);
                                if res.is_ok() {
                                    wallet.tx_lock_outputs(&slate, Some(address.to_string()), 0)?;
                                    let versioned_slate = VersionedSlate::into_version(slate, SlateVersion::V2);
                                    serde_json::to_string(&versioned_slate)?
                                } else {
                                     println!("Error: {:?}", res);
                                     "{\"error\": \"An error occurred while posting slate.\"}".to_string()
                                }
                            }
                            else {
                                println!("Error: {:?}", slate);
                               "{\"error\": \"An error occurred while generating slate.\"}".to_string()
                            }
                        } else {
                            "{\"error\": \"An error occurred sending to a keybase address. Note: keybase must be configured on startup to use with the API.\"}".to_string()
                        }
                    } else {
                        println!("Error: {:?}", address);
                        "{\"error\": \"An error occurred while parsing keybase address.\"}".to_string()
                    }
                }
            }
            IssueSendMethod::File => {
                if !body.dest.is_some() {
                    "{\"error\": \"dest was not specified.\"}".to_string()
                }
                else {
                     let destination = body.dest.unwrap();

                     let mut file = File::create(destination.clone())?;
                     let slate = wallet.initiate_send_tx(Some(destination.clone()), body.amount, body.minimum_confirmations, selection_strategy, body.num_change_outputs, body.max_outputs, body.message, None, body.version, 1, &None);
                     if slate.is_ok() {
                         let slate = slate.unwrap();
                         let versioned_slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);
                         let str_slate = serde_json::to_string(&versioned_slate)?;
                         file.write_all(str_slate.as_bytes())?;
                         wallet.tx_lock_outputs(&slate, Some(destination), 0)?;
                         "{\"success\": true}".to_string()
                     }
                     else {
                         println!("error: {:?}", slate);
                         "{\"error\": \"error generating slate.\"}".to_string()
                     }
                }
            }
            IssueSendMethod::Http => {
                if !body.dest.is_some() {
                    "{\"error\": \"dest was not specified.\"}".to_string()
                }
                else {
                     let destination = body.dest.unwrap();
                     let url = Url::parse(&format!("{}/v2/foreign", destination));

                     if url.is_ok() {

                         let slate = wallet.initiate_send_tx(
                                Some(destination.clone()),
                                body.amount,
                                body.minimum_confirmations,
                                selection_strategy,
                                body.num_change_outputs,
                                body.max_outputs,
                                body.message,
                                None,
                                body.version,
                                1,
                                &None,
                         );

                         if slate.is_ok() {
                             let slate = slate.unwrap();

                             let versioned_slate_req = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);

                             let req = json!({
                             "jsonrpc": "2.0",
                             "method": "receive_tx",
                             "id": 1,
                             "params": [
                                versioned_slate_req,
                                null,
                                null
                             ]       
                             }); 
                             let url = url.unwrap();
                             let res: Result<SlateResp, ErrorKind> = post(url.as_str(), None, &req ).map_err(|e| {
                                 let report = format!("Posting transaction slate (is recipient listening?): {}", e);
                                 println!("{}", report);
                                 ErrorKind::HttpRequest(format!("Unable to post slate to {}, {}", url.as_str(), e))
                             });

                             if res.is_ok() {
                                 let res = res.unwrap();
                                 // should be ok since we already used serde
                                 let res = serde_json::to_string(&res)?;

                                 // same
                                 let res: Value = serde_json::from_str(&res)?;

                                 if res["error"] != json!(null) {
                                     let report = format!(
                                         "Posting transaction slate: Error: {}, Message: {}",
                                         res["error"]["code"], res["error"]["message"]
                                     );      
                                     println!("{}", report);
                                     "{\"error\": \"destination returned error.\"}".to_string()
                                 } else {
                                     let slate_value = res["result"]["Ok"].clone();
                                     let slate: VersionedSlate =
                                         serde_json::from_str(&serde_json::to_string(&slate_value)?)?;
                                     let mut slate = Slate::from(slate);

                                     cli_message!(
                                         "slate [{}] received back from [{}] for [{}] MWCs",
                                         slate.id.to_string().bright_green(),
                                         url.as_str().bright_green(),
                                         amount_to_hr_string(slate.amount, false).bright_green()
                                     );

                                     wallet.tx_lock_outputs(&slate, Some(destination), 0)?;
                                     let res = wallet.finalize_slate(&mut slate, None, false);

                                     if res.is_ok() {
                                         cli_message!(
                                             "slate [{}] finalized successfully",
                                             slate.id.to_string().bright_green()
                                         );

                                         let versioned_slate = VersionedSlate::into_version(slate, SlateVersion::V2);
                                         serde_json::to_string(&versioned_slate)?
                                     } else {
                                         println!("Error finalizing slate: {:?}", res);
                                         "{\"error\": \"An error occured while finalizing slate. See stdout for details..\"}".to_string()
                                     }
                                 }

                             } else {
                                 let ret_id = wallet.get_id(slate.id);
                                 if ret_id.is_ok() {
                                     let ret = wallet.cancel(ret_id.unwrap());
                                     if ret.is_err() {
                                         println!("{}: Could not cancel failed transaction. You must manually cancel",
                                             "WARNING".bright_yellow());
                                     }
                                 } else {
                                     println!("{}: Could not cancel failed transaction. You must manually cancel",
                                             "WARNING".bright_yellow());
                                 }
                                 println!("Error: {:?}", res);
                                 "{\"error\": \"An error occured while contacting destination.\"}".to_string()

                             }
                         } else {
                             println!("Error: {:?}", slate);
                             "{\"error\": \"An error occurred while generating slate.\"}".to_string()
                         }

                     } else {
                         "{\"error\": \"Destination is invalid.\"}".to_string()
                     }
                }

            }
            _ => {
               "{\"error\": \"This method is not currently supported.\"}".to_string()
            }
        };
        Ok(res)
    }
    else {
        Ok("{\"error\": \"Could not parse send request.\"}".to_string())
    }
}

