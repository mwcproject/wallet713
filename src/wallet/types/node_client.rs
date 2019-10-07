// Copyright 2018 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common::client;
use grin_p2p::types::PeerInfoDisplay;
use grin_core::global;
use futures::stream;
use futures::Stream;
use grin_api::{LocatedTxKernel, Output, OutputListing, OutputType, Tip};
use grin_core::core::TxKernel;
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::to_hex;
use libwallet::{Error, ErrorKind, NodeClient, NodeVersionInfo, TxWrapper};
use semver::Version;
use std::collections::HashMap;
use tokio::runtime::Runtime;

#[derive(Clone)]
pub struct HTTPNodeClient {
	node_url: String,
	node_api_secret: Option<String>,
	node_version_info: Option<NodeVersionInfo>,
}

impl HTTPNodeClient {
	/// Create a new client that will communicate with the given grin node
	pub fn new(node_url: &str, node_api_secret: Option<String>) -> HTTPNodeClient {
		HTTPNodeClient {
			node_url: node_url.to_owned(),
			node_api_secret: node_api_secret,
			node_version_info: None,
		}
	}
}

impl NodeClient for HTTPNodeClient {
	fn node_url(&self) -> &str {
		&self.node_url
	}
	fn node_api_secret(&self) -> Option<String> {
		self.node_api_secret.clone()
	}

	fn set_node_url(&mut self, node_url: &str) {
		self.node_url = node_url.to_owned();
	}

	fn set_node_api_secret(&mut self, node_api_secret: Option<String>) {
		self.node_api_secret = node_api_secret;
	}

	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		if let Some(v) = self.node_version_info.as_ref() {
			return Some(v.clone());
		}
		let url = format!("{}/v1/version", self.node_url());

                let mut retval = match if global::is_mainnet() {
                        client::get::<NodeVersionInfo>(url.as_str(), self.node_api_secret(), global::ChainTypes::Mainnet)
                } else if global::is_floonet() {
                        client::get::<NodeVersionInfo>(url.as_str(), self.node_api_secret(), global::ChainTypes::Floonet)
                } else {
                        client::get::<NodeVersionInfo>(url.as_str(), self.node_api_secret(), global::ChainTypes::UserTesting)
                }

		{
			Ok(n) => n,
			Err(e) => {
				// If node isn't available, allow offline functions
				// unfortunately have to parse string due to error structure
				let err_string = format!("{}", e);
				if err_string.contains("404") {
					return Some(NodeVersionInfo {
						node_version: "1.0.0".into(),
						block_header_version: 1,
						verified: Some(false),
					});
				} else {
					error!("Unable to contact Node to get version info: {}", e);
					return None;
				}
			}
		};
		retval.verified = Some(true);
		self.node_version_info = Some(retval.clone());
		Some(retval)
	}

	/// Posts a transaction to a grin node
	fn post_tx(&self, tx: &TxWrapper, fluff: bool) -> Result<(), Error> {
		let url;
		let dest = self.node_url();
		if fluff {
			url = format!("{}/v1/pool/push_tx?fluff", dest);
		} else {
			url = format!("{}/v1/pool/push_tx", dest);
		}

                let res = if global::is_mainnet() {
                        client::post_no_ret(url.as_str(), self.node_api_secret(), tx, global::ChainTypes::Mainnet)
                } else if global::is_floonet() {
                        client::post_no_ret(url.as_str(), self.node_api_secret(), tx, global::ChainTypes::Floonet)
                } else {
                        client::post_no_ret(url.as_str(), self.node_api_secret(), tx, global::ChainTypes::UserTesting)
                };


		if let Err(e) = res {
			let report = format!("Posting transaction to node: {}", e);
			error!("Post TX Error: {}", e);
			return Err(ErrorKind::ClientCallback(report).into());
		}
		Ok(())
	}

	/// Return the chain tip from a given node
	fn get_chain_height(&self) -> Result<u64, Error> {
		let addr = self.node_url();
		let url = format!("{}/v1/chain", addr);

                let res = if global::is_mainnet() {
                        client::get::<Tip>(url.as_str(), self.node_api_secret(), global::ChainTypes::Mainnet)
                } else if global::is_floonet() {
                        client::get::<Tip>(url.as_str(), self.node_api_secret(), global::ChainTypes::Floonet)
                } else {
                        client::get::<Tip>(url.as_str(), self.node_api_secret(), global::ChainTypes::UserTesting)
                };


		match res {
			Err(e) => {
				let report = format!("Getting chain height from node: {}", e);
				error!("Get chain height error: {}", e);
				Err(ErrorKind::ClientCallback(report).into())
			}
			Ok(r) => Ok(r.height),
		}
	}

	/// Retrieve outputs from node
	fn get_outputs_from_node(
		&self,
		wallet_outputs: Vec<Commitment>,
	) -> Result<HashMap<Commitment, (String, u64, u64)>, Error> {
		let addr = self.node_url();
		// build the necessary query params -
		// ?id=xxx,yyy,zzz
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| format!("{}", to_hex(commit.as_ref().to_vec())))
			.collect();

		// build a map of api outputs by commit so we can look them up efficiently
		let mut api_outputs: HashMap<Commitment, (String, u64, u64)> = HashMap::new();
		let mut tasks = Vec::new();

		for query_chunk in query_params.chunks(120) {
			let url = format!(
				"{}/v1/chain/outputs/byids?id={}",
				addr,
				query_chunk.join(","),
			);

			if global::is_mainnet() {
                                tasks.push(client::get_async::<Vec<Output>>(
                                        url.as_str(),
                                        self.node_api_secret(),
                                        global::ChainTypes::Mainnet
                                ));
                        } else if global::is_floonet() {
                                tasks.push(client::get_async::<Vec<Output>>(
                                        url.as_str(),
                                        self.node_api_secret(),
                                        global::ChainTypes::Floonet
                                ));
                        } else {
                                tasks.push(client::get_async::<Vec<Output>>(
                                        url.as_str(),
                                        self.node_api_secret(),
                                        global::ChainTypes::UserTesting
                                ));
                        }

		}

		let task = stream::futures_unordered(tasks).collect();

		let mut rt = Runtime::new().unwrap();
		let results = match rt.block_on(task) {
			Ok(outputs) => outputs,
			Err(e) => {
				let report = format!("Getting outputs by id: {}", e);
				error!("Outputs by id failed: {}", e);
				return Err(ErrorKind::ClientCallback(report).into());
			}
		};

		for res in results {
			for out in res {
				api_outputs.insert(
					out.commit.commit(),
					(to_hex(out.commit.to_vec()), out.height, out.mmr_index),
				);
			}
		}
		Ok(api_outputs)
	}

	fn get_outputs_by_pmmr_index(
		&self,
		start_height: u64,
		max_outputs: u64,
	) -> Result<(u64, u64, Vec<(Commitment, RangeProof, bool, u64, u64)>), Error> {
		let addr = self.node_url();
		let query_param = format!("start_index={}&max={}", start_height, max_outputs);

		let url = format!("{}/v1/txhashset/outputs?{}", addr, query_param,);

		let mut api_outputs: Vec<(Commitment, RangeProof, bool, u64, u64)> = Vec::new();

                match if global::is_mainnet() {
                        	client::get::<OutputListing>(url.as_str(), self.node_api_secret(), global::ChainTypes::Mainnet)
                	} else if global::is_floonet() {
                        	client::get::<OutputListing>(url.as_str(), self.node_api_secret(), global::ChainTypes::Floonet)
                	} else {
                       		client::get::<OutputListing>(url.as_str(), self.node_api_secret(), global::ChainTypes::UserTesting)
                	}
			{
			Ok(o) => {
				for out in o.outputs {
					let is_coinbase = match out.output_type {
						OutputType::Coinbase => true,
						OutputType::Transaction => false,
					};
					api_outputs.push((
						out.commit,
						out.range_proof().unwrap(),
						is_coinbase,
						out.block_height.unwrap(),
						out.mmr_index,
					));
				}

				Ok((o.highest_index, o.last_retrieved_index, api_outputs))
			}
			Err(e) => {
				// if we got anything other than 200 back from server, bye
				error!(
					"get_outputs_by_pmmr_index: error contacting {}. Error: {}",
					addr, e
				);
				let report = format!("outputs by pmmr index: {}", e);
				Err(ErrorKind::ClientCallback(report))?
			}
		}
	}

	/// Get a kernel and the height of the block it is included in. Returns
	/// (tx_kernel, height, mmr_index)
	fn get_kernel(
		&mut self,
		excess: &Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error> {
		let version = self
			.get_version_info()
			.ok_or(libwallet::ErrorKind::ClientCallback(
				"Unable to get version".into(),
			))?;
		let version = Version::parse(&version.node_version)
			.map_err(|_| libwallet::ErrorKind::ClientCallback("Unable to parse version".into()))?;
		if version <= Version::new(2, 0, 0) {
			return Err(libwallet::ErrorKind::ClientCallback(
				"Kernel lookup not supported by node, please upgrade it".into(),
			)
			.into());
		}

		let mut query = String::new();
		if let Some(h) = min_height {
			query += &format!("min_height={}", h);
		}
		if let Some(h) = max_height {
			if query.len() > 0 {
				query += "&";
			}
			query += &format!("max_height={}", h);
		}
		if query.len() > 0 {
			query.insert_str(0, "?");
		}

		let url = format!(
			"{}/v1/chain/kernels/{}{}",
			self.node_url(),
			to_hex(excess.0.to_vec()),
			query
		);

                let res: Option<LocatedTxKernel> = if global::is_mainnet() {
                        client::get(url.as_str(), self.node_api_secret(), global::ChainTypes::Mainnet)
                } else if global::is_floonet() {
                        client::get(url.as_str(), self.node_api_secret(), global::ChainTypes::Floonet)
                } else {
                        client::get(url.as_str(), self.node_api_secret(), global::ChainTypes::UserTesting)
                }.map_err(|e| libwallet::ErrorKind::ClientCallback(format!("Kernel lookup: {}", e)))?;

		Ok(res.map(|k| (k.tx_kernel, k.height, k.mmr_index)))
	}

	/// Return total_difficulty of the chain 
        fn get_total_difficulty(&self) -> Result<u64, Error> {
                let addr = self.node_url();
                let url = format!("{}/v1/chain", addr);

                let res = if global::is_mainnet() {
                        client::get::<Tip>(url.as_str(), self.node_api_secret(), global::ChainTypes::Mainnet)
                } else if global::is_floonet() {
                        client::get::<Tip>(url.as_str(), self.node_api_secret(), global::ChainTypes::Floonet)
                } else {
                        client::get::<Tip>(url.as_str(), self.node_api_secret(), global::ChainTypes::UserTesting)
                };

                match res {
                        Err(e) => {
                                let report = format!("Getting chain difficulty from node: {}", e);
                                error!("Get diffulty error: {}", e);
                                Err(ErrorKind::ClientCallback(report).into())
                        }
                        Ok(r) => Ok(r.total_difficulty),
                }
        }

	/// Return Connected peers
        fn get_connected_peer_info(&self) -> Result<Vec<PeerInfoDisplay>, libwallet::Error> {
                let addr = self.node_url();
                let url = format!("{}/v1/peers/connected", addr);
                
                let peers = if global::is_mainnet() {
                        client::get::<Vec<PeerInfoDisplay>>(url.as_str(), self.node_api_secret(), global::ChainTypes::Mainnet)
                } else if global::is_floonet() {
                        client::get::<Vec<PeerInfoDisplay>>(url.as_str(), self.node_api_secret(), global::ChainTypes::Floonet)
                } else {
                        client::get::<Vec<PeerInfoDisplay>>(url.as_str(), self.node_api_secret(), global::ChainTypes::UserTesting)
                }.map_err(|e| libwallet::ErrorKind::ClientCallback(format!("get_connected_peer_info: {}", e)))?;
                
                Ok(peers)
        }
}
