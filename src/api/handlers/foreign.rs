use gotham::handler::{HandlerFuture };
use serde_json::Value;
use grin_core::core;
use colored::Colorize;
use gotham::state::{FromState, State};
use hyper::body::Chunk;
use hyper::{Body, Response, StatusCode};
use crate::api::router::{trace_create_response, trace_state_and_body, WalletContainer};
use grin_wallet_libwallet::{BlockFees, Slate};
use common::Error;

pub fn v2foreign(state: State) -> Box<HandlerFuture> {
        Box::new(super::executor::RunHandlerInThread::new(state, handle_v2foreign ) )
}

fn handle_v2foreign(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
        trace_state_and_body(state, body);
        let res = String::from_utf8(body.to_vec())?;

        let res: Value = serde_json::from_str(&res).unwrap();
        if res["error"] != json!(null) {
            let report = format!(
                "Posting transaction slate: Error: {}, Message: {}",
                res["error"]["code"], res["error"]["message"]
            );
            println!("{}", report);
        }

        if res["method"] == "check_version" {

            let slate_resp = json!({
                "id": 1,
                "jsonrpc": "2.0",
                "result": {
                        "Ok": { 
                                "foreign_api_version": 2,
                                "supported_slate_versions": [
                                        "V3",
                                        "V2"
                                ]
                        }
                }
            });


            Ok(trace_create_response(
                &state,
                StatusCode::OK,
                mime::APPLICATION_JSON,
                serde_json::to_string(&slate_resp)?,
            ))
        } else {

            let slate_value = res["params"][0].clone();
        
            let mut slate = Slate::deserialize_upgrade(&serde_json::to_string(&slate_value).unwrap())?;
            let id;

            if slate.num_participants > slate.participant_data.len() {
                let message = &slate.participant_data[0].message;
                let display_from = "https listener";
                if message.is_some() {
                    id = message.clone().unwrap();
                    cli_message!(
                    "slate [{}] received from [{}] for [{}] MWCs. Message: [\"{}\"]",
                    slate.id.to_string().bright_green(),
                    display_from.bright_green(),
                    core::amount_to_hr_string(slate.amount, false).bright_green(),
                    id.bright_green()
                    );
                } else {
                    id = "".to_string();
                    cli_message!(
                    "slate [{}] received from [{}] for [{}] MWCs.",
                    slate.id.to_string().bright_green(),
                    display_from.bright_green(),
                    core::amount_to_hr_string(slate.amount, false).bright_green()
                    );
                }
            } else {
                id = "".to_string();
            }

            let wallet = WalletContainer::borrow_from(&state).lock()?;
            wallet.process_sender_initiated_slate(Some(format!("https://{}", id)), &mut slate, None,
                                              None, Some( &wallet.active_account ) )?;

            let slate_resp = json!({
                                   "id": 1,
                                   "jsonrpc": "2.0",
                                   "result": {             
                                       "Ok": slate
                                   }
                               });


            Ok(trace_create_response(
            &state,
            StatusCode::OK,
            mime::APPLICATION_JSON,
            serde_json::to_string(&slate_resp)?,
            ))
        }

}


pub fn receive_tx(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_receive_tx ) )
}

fn handle_receive_tx(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state_and_body(state, body);
    let mut slate = Slate::deserialize_upgrade(&String::from_utf8(body.to_vec())?)?;
    let wallet = WalletContainer::borrow_from(&state).lock()?;
    wallet.process_sender_initiated_slate(None, &mut slate, None, None, Some(&wallet.active_account) )?;
    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_string(&slate)?,
    ))
}

pub fn build_coinbase(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_build_coinbase ) )
}

fn handle_build_coinbase(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state_and_body(state, body);
    let block_fees: BlockFees = serde_json::from_slice(&body)?;
    let wallet = WalletContainer::borrow_from(&state).lock()?;
    let cb_data = wallet.build_coinbase(&block_fees)?;
    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_string(&cb_data)?,
    ))
}

pub fn receive_invoice(state: State) -> Box<HandlerFuture> {
    Box::new(super::executor::RunHandlerInThread::new(state, handle_receive_invoice ) )
}

fn handle_receive_invoice(state: &State, body: &Chunk) -> Result<Response<Body>, Error> {
    trace_state_and_body(state, body);
    let mut slate: Slate = serde_json::from_slice(&body)?;
    let wallet = WalletContainer::borrow_from(&state).lock()?;
    wallet.process_receiver_initiated_slate(&mut slate, None)?;
    Ok(trace_create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_string(&slate)?,
    ))
}
