use failure::Error;
use grin_core::core::amount_to_hr_string;
use colored::Colorize;
use grin_api::Output;
use grin_util as util;
use url::Url;
use std::sync::Arc;
use grin_api::client::post;
use common::config::Wallet713Config;
use wallet::wallet::Wallet;
use std::collections::HashMap;
use grin_util::secp::pedersen::Commitment;
use wallet::types::slate::versions::VersionedSlate;
use grin_util::to_hex;
use std::clone::Clone;
use serde_json::Value;
use futures::future;
use futures::stream;
use futures::{Future, Stream};
use gotham::handler::{HandlerFuture, IntoHandlerError, IntoResponse};
use gotham::helpers::http::response::create_empty_response;
use gotham::helpers::http::response::create_response;
use gotham::state::{FromState, State};
use hyper::body::Chunk;
use hyper::{Request, Body, Response, StatusCode};
use std::str::FromStr;
use uuid::Uuid;
use grin_core::global::ChainTypes;
use grin_core::global;
use grin_util::to_base64;
use hyper::header::{AUTHORIZATION};

use crate::api::error::ApiError;
use crate::api::router::{
    trace_create_response, trace_state, trace_state_and_body, WalletContainer,
};
use crate::broker::Publisher;
use crate::common::ErrorKind;
use crate::contacts::{Address, MWCMQSAddress, KeybaseAddress};
use crate::wallet::types::Slate;

type ResponseContentFuture = Box<dyn Future<Item = Vec<u8>, Error = hyper::Error> + Send>;
type ResponseOutputFuture = Box<dyn Future<Item = Vec<Output>, Error = hyper::Error> + Send>;

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

fn http_get(url_str: &str, api_secret: Option<String>, chain_type: ChainTypes) -> ResponseContentFuture {
    let https = hyper_tls::HttpsConnector::new(1).unwrap();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    let mut req = Request::builder();


    if let Some(api_secret) = api_secret {
        let basic_auth = if chain_type == global::ChainTypes::Floonet {
           format!("Basic {}", to_base64(&format!("mwcfloo:{}", api_secret)))
        } else if chain_type == global::ChainTypes::Mainnet {
            format!("Basic {}", to_base64(&format!("mwcmain:{}", api_secret)))
        } else {
            format!("Basic {}", to_base64(&format!("mwc:{}", api_secret)))
        };
        req.header(AUTHORIZATION, basic_auth);
    };

    let req = req
        .method("GET")
        .uri(url_str)
        .body(Body::empty())
        .unwrap();

    let f = client.request(req).and_then(|response| {
        response
            .into_body()
            .concat2()
            .and_then(|full_body| Ok(full_body.to_vec()))
    });

    Box::new(f)
}

pub fn retrieve_outputs(state: State) -> (State, Response<Body>) {
    let res = match handle_retrieve_outputs(&state) {
        Ok(res) => res,
        Err(e) => ApiError::new(e).into_handler_error().into_response(&state),
    };
    (state, res)
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct RetrieveOutputsQueryParams {
    refresh: Option<bool>,
    show_spent: Option<bool>,
    tx_id: Option<u32>,
}

fn handle_retrieve_outputs(state: &State) -> Result<Response<Body>, Error> {
    trace_state(state);
    let &RetrieveOutputsQueryParams {
        refresh,
        show_spent,
        tx_id,
    } = RetrieveOutputsQueryParams::borrow_from(&state);
    let wallet = WalletContainer::borrow_from(&state).lock()?;
    let response =
        wallet.retrieve_outputs(show_spent.unwrap_or(false), refresh.unwrap_or(false), tx_id)?;
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
        return Err(ErrorKind::ModelNotFound.into());
    }

    if txs[0].tx_slate_id.is_none() {
        return Err(ErrorKind::ModelNotFound.into());
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
    let config = WalletContainer::borrow_from(&state).get_config().unwrap();
    let url = format!("{}/v1/chain", config.mwc_node_uri());

    let data_future: ResponseContentFuture = Box::new(
        http_get(&url, config.mwc_node_secret(), config.chain.clone().unwrap()).and_then(move |body| {
            let res = String::from_utf8_lossy(&body);
            let res: Value = serde_json::from_str(&res).unwrap();
            let ret = format!("{{\"height\": {} }}", res.get("height").unwrap().as_u64().unwrap()).as_bytes().to_vec();
            Ok(ret)
        })
    );

    Box::new(data_future.then(move |result| match result {
        Ok(data) => {
            let res = create_response(&state, StatusCode::OK, mime::TEXT_PLAIN, data);
            Ok((state, res))
        }
        Err(err) => {
            println!("Error occured {:?}", err);
            let res = create_response(&state, StatusCode::OK, mime::TEXT_PLAIN, "{\"error\": \"could not connect to node\"}");
            Ok((state, res))
        },
    }))
}

pub fn retrieve_summary_info(state: State) -> Box<HandlerFuture> {
    let res = refresh_processor(state, ProcType::SummaryInfo).unwrap();
    res
}

pub fn finalize_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_finalize_tx ) )
}

pub fn handle_finalize_tx(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state_and_body(state, body);
    let mut slate: Slate = serde_json::from_slice(&body)?;
    let container = WalletContainer::borrow_from(&state);
    let wallet = container.lock()?;

    wallet.finalize_slate(&mut slate, None)?;

    Ok(create_empty_response(&state, StatusCode::OK))
}

pub fn cancel_tx(state: State) -> Box<HandlerFuture> {
    let res = refresh_processor(state, ProcType::Cancel).unwrap();
    res
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
    let slate: Slate = serde_json::from_slice(&body)?;
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
    max_outputs: usize,
    num_change_outputs: usize,
    selection_strategy_is_use_all: bool,
    message: Option<String>,
    version: Option<u16>,
}

#[derive(PartialEq)]
pub enum ProcType {
    SummaryInfo,
    Cancel,
}


pub fn issue_send_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_issue_send_tx ) )
}

pub fn handle_issue_send_tx(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    let container = WalletContainer::borrow_from(state);
    let config = WalletContainer::borrow_from(state).get_config().unwrap();
    let wallet = container.lock().unwrap();
    let res = process_handle_issue_send_tx(&container, &config, &wallet, body);

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

pub fn refresh_processor(mut state: State, ptype: ProcType) -> Result<Box<HandlerFuture>, Error> {
    let future = Body::take_from(&mut state)
        .concat2()
        .then(|_body| {

        let config = WalletContainer::borrow_from(&state).get_config().unwrap();

        let url = format!("{}/v1/chain", config.mwc_node_uri());

        let data_future: ResponseContentFuture = Box::new(
            http_get(&url, config.mwc_node_secret(), config.chain.clone().unwrap()).and_then(move |body| {
                let res = String::from_utf8_lossy(&body);
                let res: Value = serde_json::from_str(&res).unwrap();
                let ret = format!("{}", res.get("height").unwrap().as_u64().unwrap()).as_bytes().to_vec();
                Ok(ret)
            })
        );

        data_future.then(|result| {
            let container = WalletContainer::borrow_from(&state).to_owned();
            let wallet = container.lock().unwrap();
            let config = container.get_config().unwrap();
            let is_error;

            let height = match result {
                Ok(res) => {
                    is_error = false;
                    Arc::new(String::from_utf8_lossy(&res).parse::<u64>().unwrap())
                },
                Err(_e) => {
                    is_error = true;
                    Arc::new(0)
                }
            };


            let addr = format!("{}", config.mwc_node_uri());
            let wallet_outputs = wallet.get_outputs().unwrap();
            let query_params: Vec<String> = wallet_outputs
                        .iter()
                        .map(|commit| format!("{}", to_hex(commit.0.as_ref().to_vec())))
                        .collect();

            // build a map of api outputs by commit so we can look them up efficiently
            let _api_outputs: HashMap<Commitment, (String, u64, u64)> = HashMap::new();
            let mut count = 0;
            let mut url_vec = Vec::new();

            for query_chunk in query_params.chunks(120) {
                count = count + 1;
                let url = format!("{}/v1/chain/outputs/byids?id={}", addr, query_chunk.join(","),);
                url_vec.push((url,config.mwc_node_secret()));
            }

            let handle_outputs: ResponseOutputFuture = if !is_error {
                Box::new(
                    stream::iter_ok(url_vec).fold(Vec::new(), move |mut accumulator, url_data| {
                        let url = url_data.0;
                        let secret = url_data.1;
                        let chain_type =
                            if global::is_mainnet() { global::ChainTypes::Mainnet }
                            else if global::is_floonet() { global::ChainTypes::Floonet }
                            else { global::ChainTypes::UserTesting };
                        http_get(&url, secret, chain_type).and_then(move |body| {
                            let body_parsed = String::from_utf8_lossy(&body);
                            let res: Value = serde_json::from_str(&body_parsed).unwrap();
                            let mut outputs = Vec::new();
                            for elem in res.as_array().unwrap() {
                                let id = elem.get("commit").unwrap().as_str().unwrap();
                                let c_vec = util::from_hex(String::from(id)).unwrap();
                                let commit = Commitment::from_vec(c_vec);
                                let output = Output::new(&commit,
                                             elem.get("height").unwrap().as_u64().unwrap(),
                                             elem.get("mmr_index").unwrap().as_u64().unwrap());
                                outputs.push(output);
                            }

                            accumulator.extend(outputs);
                            Ok(accumulator)
                        })
                     })
                 )
             } else {
                 Box::new(
                     stream::iter_ok(url_vec).fold(Vec::new(), move |accumulator, _url_data| {
                         // only way we were able to make rust behave by sending to google here.
                         // TODO: improve this. Should not actually make the request.
                         let url = "http://www.google.com".to_string();
                         let chain_type = global::ChainTypes::Mainnet;
                         http_get(&url, None, chain_type).and_then(move |_body| {
                             Ok(accumulator)
                         })
                     })
                 )
             };

             let fut_out = 
                 handle_outputs.then(move |accumulator| {
                 let container = WalletContainer::borrow_from(&state).to_owned();
                 let wallet = container.lock().unwrap();
                 let height = Arc::clone(&height);

                 if ptype == ProcType::Cancel {
                     let &CancelTransactionQueryParams { id } = CancelTransactionQueryParams::borrow_from(&state);
                     match process_handle_cancel(&wallet, id, *height, &accumulator.unwrap()) {
                         Ok(res) => {
                             let res = trace_create_response(
                                 &state,
                                 StatusCode::OK,
                                 mime::APPLICATION_JSON,
                                 res
                             );
                             future::ok((state, res))
                         },
                         Err(e) => future::err((state, ApiError::new(e).into_handler_error())),
                     }
                 } else { // ProcType::SummaryInfo
                     match process_handle_summary_info(&wallet, *height, &accumulator.unwrap()) {
                         Ok(res) => {
                             let res = trace_create_response(
                                 &state,
                                 StatusCode::OK,
                                 mime::APPLICATION_JSON,
                                 res
                             );
                             future::ok((state, res))
                         },
                         Err(e) => future::err((state, ApiError::new(e).into_handler_error())),
                     }
                 }
             });
            fut_out
        })
    });

    Ok(Box::new(future))
}

pub fn process_handle_cancel(wallet: &Wallet, id: u32, height: u64, accumulator: &Vec<Output>) -> Result<String, Error> {
    let response = wallet.cancel(id, Some(height), Some(accumulator.to_vec()));


    let ret = 
    if response.is_err() {
        let full = format!("error = {:?}", response);
        if full.contains("TransactionDoesntExist") {
            format!("{{\"error\": \"TransactionDoesntExist\"}}")
        }
        else if full.contains("TransactionNotCancellable") {
            format!("{{\"error\": \"TransactionNotCancellable\"}}")
        } else {
            println!("Unknown error = {:?}", response);
            format!("{{\"error\": \"Unknown\"}}")
        }
    } else {
        format!("{{\"success\": true}}")
    };

    Ok(ret)
}

pub fn process_handle_summary_info(wallet: &Wallet, height: u64, accumulator: &Vec<Output>) -> Result<String, Error> {
    let response = wallet.retrieve_summary_info(true, Some(height), Some(accumulator.to_vec()))?;
    let response = serde_json::to_string(&response)?;
    Ok(response)
}

pub fn process_handle_issue_send_tx(container: &WalletContainer, config: &Wallet713Config, wallet: &Wallet, body: &Chunk) -> Result<String, Error> {
    let body: Result<IssueSendBody, serde_json::Error> = serde_json::from_slice(&body);
    if body.is_ok() {
        let body = body.unwrap();
        let selection_strategy = match body.selection_strategy_is_use_all {
            true => "all",
            false => "",
        };
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
                                None,
                                None,
                            );

                            if slate.is_ok() {
                                let slate = slate.unwrap();
                                let res = publisher.post_slate(&slate, &address);
                                if res.is_ok() {
                                    serde_json::to_string(&slate)?
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
                                None,
                                None,
                            );

                            if slate.is_ok() {
                                let slate = slate.unwrap();
                                let res = publisher.post_slate(&slate, &address);
                                if res.is_ok() {
                                    serde_json::to_string(&slate)?
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
            IssueSendMethod::Http => {
                if !body.dest.is_some() {
                    "{\"error\": \"dest was not specified.\"}".to_string()
                }
                else {
                     let destination = body.dest.unwrap();
                     let url = Url::parse(&format!("{}/v2/foreign", destination));

                     if url.is_ok() {

                         let slate = wallet.initiate_send_tx(
                                Some(destination),
                                body.amount,
                                body.minimum_confirmations,
                                selection_strategy,
                                body.num_change_outputs,
                                body.max_outputs,
                                body.message,
                                None,
                                body.version,
                                1,
                                None,
                                None,
                         );

                         if slate.is_ok() {
                             let slate = slate.unwrap();

                             let req = json!({
                             "jsonrpc": "2.0",
                             "method": "receive_tx",
                             "id": 1,
                             "params": [
                                slate,
                                null,
                                null
                             ]       
                             }); 
                             let url = url.unwrap();
                             let res: Result<SlateResp, ErrorKind> = post(url.as_str(), None, &req, config.chain.clone().unwrap()).map_err(|e| {
                                 let report = format!("Posting transaction slate (is recipient listening?): {}", e);
                                     println!("{}", report);
                                     ErrorKind::HttpRequest
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

                                     let res = wallet.finalize_slate(&mut slate, None);

                                     if res.is_ok() {
                                         cli_message!(
                                             "slate [{}] finalized successfully",
                                             slate.id.to_string().bright_green()
                                         );
                                         serde_json::to_string(&slate)?
                                     } else {
                                         println!("Error finalizing slate: {:?}", res);
                                         "{\"error\": \"An error occured while finalizing slate. See stdout for details..\"}".to_string()
                                     }
                                 }

                             } else {
                                 let ret_id = wallet.get_id(slate.id);
                                 if ret_id.is_ok() {
                                     let ret = wallet.cancel(ret_id.unwrap(), None, None);
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

