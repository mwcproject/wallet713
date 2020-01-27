use std::fmt;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use grin_core::global::ChainTypes;
use grin_util::logger::LoggingConfig;

use super::crypto::{public_key_from_secret_key, PublicKey, SecretKey};
use super::ErrorKind;
use super::is_cli;
use crate::contacts::{GrinboxAddress, MWCMQSAddress, DEFAULT_GRINBOX_PORT};
use crate::common::Error;

const WALLET713_HOME: &str = ".mwc713";
const WALLET713_DEFAULT_CONFIG_FILENAME: &str = "wallet713.toml";

#[derive(Clone, Debug, Serialize, Deserialize, StateData, PartialEq)]
pub struct Wallet713Config {
    pub chain: ChainTypes,
    pub wallet713_data_path: String,
    pub keybase_binary: Option<String>,
    pub mwcmq_domain: Option<String>,
    pub mwcmq_port: Option<u16>,
    pub mwcmqs_domain: Option<String>,
    pub mwcmqs_port: Option<u16>,
    pub grinbox_protocol_unsecure: Option<bool>,
    pub grinbox_address_index: Option<u32>,
    pub mwc_node_uri: Option<String>,
    pub mwc_node_secret: Option<String>,
    pub grinbox_listener_auto_start: Option<bool>,
    pub keybase_listener_auto_start: Option<bool>,
    pub max_auto_accept_invoice: Option<u64>,
    pub default_keybase_ttl: Option<String>,
    pub owner_api: Option<bool>,
    pub owner_api_address: Option<String>,
    pub owner_api_secret: Option<String>,
    pub owner_api_include_foreign: Option<bool>,
    pub foreign_api: Option<bool>,
    pub disable_history: Option<bool>,
    pub foreign_api_address: Option<String>,
    pub foreign_api_secret: Option<String>,

    /// If enabled both tls_certificate_file and tls_certificate_key, TSL will be applicable to all rest API
    /// TLS certificate file
    pub tls_certificate_file: Option<String>,
    /// TLS certificate private key file
    pub tls_certificate_key: Option<String>,

    #[serde(skip)]
    pub config_home: Option<String>,
    #[serde(skip)]
    pub grinbox_address_key: Option<SecretKey>,

    // Wallet state update frequency. In none, no updates will be run in the background.
    pub wallet_updater_frequency_sec: Option<u32>,
}

impl Default for Wallet713Config{
    fn default() -> Wallet713Config {
        Wallet713Config::default(&ChainTypes::Mainnet)
    }
}

impl Wallet713Config {

    pub fn default(chain: &ChainTypes) -> Wallet713Config {
        Wallet713Config {
            chain: chain.clone(),
            wallet713_data_path: "wallet713_data".to_string(),
            keybase_binary: None,
            mwcmq_domain: None,
            mwcmq_port: None,
            mwcmqs_domain: None,
            mwcmqs_port: None,
            grinbox_protocol_unsecure: None,
            grinbox_address_index: None,
            mwc_node_uri: None,
            mwc_node_secret: None,
            grinbox_listener_auto_start: None,
            keybase_listener_auto_start: None,
            max_auto_accept_invoice: None,
            default_keybase_ttl: Some("24h".to_string()),
            owner_api: None,
            owner_api_address: None,
            owner_api_secret: None,
            owner_api_include_foreign: Some(false),
            foreign_api: None,
            disable_history: None,
            foreign_api_address: None,
            foreign_api_secret: None,
            tls_certificate_file: None,
            tls_certificate_key: None,
            config_home: None,
            grinbox_address_key: None,
            wallet_updater_frequency_sec: None,
        }
    }


    pub fn exists(config_path: Option<&str>, chain: &ChainTypes) -> Result<bool, Error> {
        let default_path_buf = Wallet713Config::default_config_path(chain)?;
        let default_path = default_path_buf.to_str().unwrap();
        let config_path = config_path.unwrap_or(default_path);
        Ok(Path::new(config_path).exists())
    }

    pub fn from_file(
        config_path: Option<&str>,
        chain: &ChainTypes,
    ) -> Result<Wallet713Config, Error> {
        let default_path_buf = Wallet713Config::default_config_path(chain)?;
        let default_path = default_path_buf.to_str().unwrap();
        let config_path = config_path.unwrap_or(default_path);
        let mut file = File::open(config_path)?;
        let mut toml_str = String::new();
        file.read_to_string(&mut toml_str)?;
        let mut config: Wallet713Config = toml::from_str(&toml_str[..])?;
        config.config_home = Some(config_path.to_string());
        Ok(config)
    }

    pub fn default_config_path(chain: &ChainTypes) -> Result<PathBuf, Error> {
        let mut path = Wallet713Config::default_home_path(chain)?;
        path.push(WALLET713_DEFAULT_CONFIG_FILENAME);
        Ok(path)
    }

    pub fn default_home_path(chain: &ChainTypes) -> Result<PathBuf, Error> {
        let mut path = match dirs::home_dir() {
            Some(home) => home,
            None => std::env::current_dir()?,
        };

        path.push(WALLET713_HOME);
        path.push(chain.shortname());
        std::fs::create_dir_all(path.as_path())?;
        Ok(path)
    }

    pub fn to_file(&mut self, config_path: Option<&str>) -> Result<(), Error> {
        let default_path_buf = Wallet713Config::default_config_path(&self.chain)?;
        let default_path = default_path_buf.to_str().unwrap();
        let config_path = config_path.unwrap_or(default_path);
        let toml_str = toml::to_string(&self)?;
        let mut f = File::create(config_path)?;
        f.write_all(toml_str.as_bytes())?;
        self.config_home = Some(config_path.to_string());
        Ok(())
    }

    pub fn get_mwcmqs_address(&self) -> Result<MWCMQSAddress, Error> {
        let public_key = self.get_grinbox_public_key()?;
        Ok(MWCMQSAddress::new(
            public_key,
            Some(self.mwcmqs_domain()),
            self.mwcmqs_port,
        ))
    }

    pub fn disable_history(&self) -> bool {
        self.disable_history.unwrap_or(false)
    }

    pub fn get_mwcmqs_secret_key(&self) -> Result<SecretKey, Error> {
        self.grinbox_address_key.clone()
            .ok_or_else(|| ErrorKind::NoWallet.into())
    }

    pub fn grinbox_protocol_unsecure(&self) -> bool {
        self.grinbox_protocol_unsecure.unwrap_or(cfg!(windows))
    }

    pub fn get_mwcmq_domain(&self) -> String {
         self.mwcmq_domain.clone().unwrap_or("mq.mwc.mw".to_string())
    }

    pub fn mwcmqs_domain(&self) -> String {
        self.mwcmqs_domain.clone().unwrap_or("mqs.mwc.mw".to_string())
    }

    pub fn mwcmqs_port(&self) -> u16 {
        self.mwcmqs_port.unwrap_or(443)
    }

    pub fn grinbox_address_index(&self) -> u32 {
        self.grinbox_address_index.unwrap_or(0)
    }

    pub fn get_grinbox_address(&self) -> Result<GrinboxAddress, Error> {
        let public_key = self.get_grinbox_public_key()?;
        Ok(GrinboxAddress::new(
            public_key,
            Some(self.get_mwcmq_domain()),
            self.mwcmq_port,
        ))
    }

    pub fn get_grinbox_public_key(&self) -> Result<PublicKey, Error> {
        public_key_from_secret_key(&self.get_grinbox_secret_key()?)
    }

    pub fn get_grinbox_secret_key(&self) -> Result<SecretKey, Error> {
        self.grinbox_address_key.clone()
            .ok_or_else(|| ErrorKind::NoWallet.into())
    }

    // mwc-wallet using top level dir + data dir. We need to follow it
    pub fn get_top_level_directory(&self) -> Result<String, Error> {
        let dir = String::from( self.get_data_path()?.parent().unwrap().to_str().unwrap() );
        Ok(dir)
    }

    // mwc-wallet using top level dir + data dir. We need to follow it
    pub fn get_wallet_data_directory(&self) -> Result<String, Error> {
        let wallet_dir = String::from(self.get_data_path()?.file_name().unwrap().to_str().unwrap());
        Ok(wallet_dir)
    }

    pub fn get_data_path(&self) -> Result<PathBuf, Error> {
        let mut data_path = PathBuf::new();
        data_path.push(self.wallet713_data_path.clone());
        if data_path.is_absolute() {
            return Ok(data_path);
        }

        let mut data_path = PathBuf::new();
        data_path.push(
            self.config_home
                .clone()
                .unwrap_or(WALLET713_DEFAULT_CONFIG_FILENAME.to_string()),
        );
        data_path.pop();
        data_path.push(self.wallet713_data_path.clone());
        Ok(data_path)
    }

    pub fn get_data_path_str(&self) -> Result<String, Error> {
        let path_str = self.get_data_path()?.to_str().unwrap().to_owned();
        Ok(path_str)
    }

    pub fn mwc_node_uri(&self) -> String {
        let chain_type = self.chain.clone();
        self.mwc_node_uri.clone().unwrap_or(match chain_type {
            ChainTypes::Mainnet => String::from("https://mwc713.mwc.mw"),
            _ => String::from("https://mwc713.floonet.mwc.mw"),
        })
    }

    pub fn mwc_node_secret(&self) -> Option<String> {
        let chain_type = self.chain.clone();
        match self.mwc_node_uri {
            Some(_) => self.mwc_node_secret.clone(),
            None => match chain_type {
                ChainTypes::Mainnet => Some(String::from("11ne3EAUtOXVKwhxm84U")),
                _ => Some(String::from("11ne3EAUtOXVKwhxm84U")),
            },
        }
    }

    pub fn grinbox_listener_auto_start(&self) -> bool {
        self.grinbox_listener_auto_start.unwrap_or(is_cli())
    }

    pub fn keybase_listener_auto_start(&self) -> bool {
        self.keybase_listener_auto_start.unwrap_or(false)
    }

    pub fn owner_api_address(&self) -> String {
        let chain_type = self.chain.clone();
        self.owner_api_address
            .as_ref()
            .map(|a| a.clone())
            .unwrap_or_else(|| match chain_type {
                ChainTypes::Mainnet => String::from("127.0.0.1:3420"),
                _ => String::from("127.0.0.1:13420"),
            })
    }

    pub fn foreign_api_address(&self) -> String {
        let chain_type = self.chain.clone();
        self.foreign_api_address
            .as_ref()
            .map(|a| a.clone())
            .unwrap_or_else(|| match chain_type {
                ChainTypes::Mainnet => String::from("127.0.0.1:3415"),
                _ => String::from("127.0.0.1:13415"),
            })
    }

    pub fn owner_api(&self) -> bool {
        self.owner_api.unwrap_or(false)
    }

    pub fn foreign_api(&self) -> bool {
        self.foreign_api.unwrap_or(false)
    }

    /// If enabled both tls_certificate_file and tls_certificate_key, TSL will be applicable to all rest API
  /// TLS certificate file
    pub fn is_tls_enabled(&self) -> bool {
        self.tls_certificate_file.is_some() && self.tls_certificate_key.is_some()
    }
}

impl fmt::Display for Wallet713Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "wallet713_data_path={}\nmwcmq_port={}\nmwc_node_uri={}\nmwc_node_secret={}",
               self.wallet713_data_path,
               self.mwcmq_port.unwrap_or(DEFAULT_GRINBOX_PORT),
               self.mwc_node_uri.clone().unwrap_or(String::from("provided by vault713")),
               "{...}")?;
        Ok(())
    }
}

/// Error type wrapping config errors.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ConfigError {
	/// Error with parsing of config file
	ParseError(String, String),

	/// Error with fileIO while reading config file
	FileIOError(String, String),

	/// No file found
	FileNotFoundError(String),

	/// Error serializing config values
	SerializationError(String),
}

impl fmt::Display for ConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			ConfigError::ParseError(ref file_name, ref message) => write!(
				f,
				"Error parsing configuration file at {} - {}",
				file_name, message
			),
			ConfigError::FileIOError(ref file_name, ref message) => {
				write!(f, "{} {}", message, file_name)
			}
			ConfigError::FileNotFoundError(ref file_name) => {
				write!(f, "Configuration file not found: {}", file_name)
			}
			ConfigError::SerializationError(ref message) => {
				write!(f, "Error serializing configuration: {}", message)
			}
		}
	}
}

impl From<io::Error> for ConfigError {
	fn from(error: io::Error) -> ConfigError {
		ConfigError::FileIOError(
			String::from(""),
			String::from(format!("Error loading config file: {}", error)),
		)
	}
}

/// Wallet should be split into a separate configuration file
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfig {
	/// Keep track of the file we've read
	pub config_file_path: Option<PathBuf>,
	/// Wallet members
	pub members: Option<GlobalWalletConfigMembers>,
}

/// Wallet internal members
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfigMembers {
	/// Wallet configuration
	#[serde(default)]
	pub wallet: Wallet713Config,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
