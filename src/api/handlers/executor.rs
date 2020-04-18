use futures::{Poll};
use futures::{Future, Stream};
use gotham::handler::HandlerError;
use gotham::state::{FromState, State};
use hyper::body::Chunk;
use hyper::{Body, Response, StatusCode};

use common::Arc;
use crate::common::{Error};
use tokio::prelude::Async;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use gotham::helpers::http::response::create_response;


pub struct RunningTask {
    task: Option<futures::task::Task>
}

pub struct RunHandlerInThread {
    // running flag is modifiable from worker thread and Poll.
    running: Arc< AtomicBool >,
    task: Arc< std::sync::Mutex< RunningTask > >,
    // from Poll only,
    task_set: bool,

    // Need option because join require ownership transfer. That is why can't belong to 'self' dicertly
    // (State, Result<Response<Body>>)  - resulting from API call as required by gotham
    worker_thread: Option<thread::JoinHandle<(State, Result<Response<Body>, Error>)>>,
}

impl RunHandlerInThread
{
    pub fn new(mut state: State, handler:  fn(state: &State, body: &Chunk) -> Result<Response<Body>, Error> ) -> RunHandlerInThread {
        // 'self' variables
        let running = Arc::new( AtomicBool::new(true));
        let task= Arc::new( std::sync::Mutex::new( RunningTask{task:None} ) );

        // thread variables to move
        let thr_task = task.clone();
        let thr_running = running.clone();
        let worker_thread = thread::spawn(move || {

            let result = match Body::take_from(&mut state).concat2().wait() {
                Ok(body) => handler(&state, &body),
                Err(e) => Err(  failure::Error::from( e) )
            };

            thr_running.store(false, Ordering::Relaxed);

            let rt = thr_task.lock().unwrap();

            if let Some(ref task) = rt.task {
                task.notify();
            }

            (state, result)
        });


        Self { running, task, task_set: false, worker_thread: Some(worker_thread) }
    }
}

impl Future for RunHandlerInThread
{
    type Item = (State, Response<Body>);
    type Error = (State, HandlerError);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if ! self.task_set {
            // Update current task. at the first polling.
            // Task is needed by thread to notify future executor that job is done
            self.task.lock().unwrap().task = Some( futures::task::current() );
            self.task_set = true;
        }

        if self.running.load(Ordering::Relaxed) {
            // We are still running.
            Ok(Async::NotReady)
        } else {

            // The job is done. From the thread we should be able to reprieve the results.
            // Because of all ownership staff we can process this once only.
            // Result Must be OK with Ready or Error.
            // In this case futures executor guarantee call it once and satisfy get tread data once limitation


            // JoinHandle::join required ownership transfer. That is why it can be done once.
            if let Some(thr_info) = self.worker_thread.take() {
                // Gettign results from the task
                let (state, result) = thr_info.join().unwrap();
                match result {
                    // Happy path, API was completed with success.
                    Ok( body ) => Ok(Async::Ready( (state, body ) )),
                    // API was failed. Normally it return some error string.
                    // We want to print that that line at the API.
                    // Note: Error string normally has escape chracters, we are removing them by filter_escape_symbols
                    Err(err) => {
                        // Body has to be processed before because of 'state' ownership
                        let body = create_response(&state, StatusCode::BAD_REQUEST, mime::APPLICATION_JSON,
                                                   format!( "{{\"error\" : \"{}\" }}",
                                                            filter_escape_symbols(&format!("{}", err))) );
                        Ok(Async::Ready((state,body)))
                    }
                }

            }
            else {
                // Likely double processing. See comments above.
                panic!("Background thread for REST API died or double processed!");
            }
        }
    }
}

// Filter out all escape sequences. Wallet reporting errors with 'colored' chars. It is not good for REST API
fn filter_escape_symbols( s: &str ) -> String {
    let mut res = String::new();

    let mut in_esc = false;
    let esc_symbol = std::char::from_u32(27).unwrap();
    for ch in s.chars() {
        if ch == esc_symbol {
            in_esc = true;
        }

        if !in_esc {
            res.push(ch);
        }

        if ch=='m' {
            in_esc = false;
        }
    }

    res
}
