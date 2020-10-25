use std::fmt;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use grin_core::global::ChainTypes;
use grin_util::logger::LoggingConfig;

use grin_util::secp::key::PublicKey;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use crate::contacts::{ DEFAULT_GRINBOX_PORT};
use crate::common::Error;
use grin_wallet_impls::MWCMQSAddress;
use grin_wallet_config::{MQSConfig, TorConfig};
use contacts::{DEFAULT_MWCMQS_DOMAIN, DEFAULT_MWCMQS_PORT};
use std::collections::BTreeMap;

const WALLET713_HOME: &str = ".mwc713";
const WALLET713_DEFAULT_CONFIG_FILENAME: &str = "wallet713.toml";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Wallet713Config {
    pub chain: ChainTypes,
    pub wallet713_data_path: String,
    pub keybase_binary: Option<String>,
    pub mwcmq_port: Option<u16>,
    pub mwcmqs_domain: Option<String>,
    pub mwcmqs_port: Option<u16>,
    pub grinbox_address_index: Option<u32>,
    pub socks_addr: Option<String>,
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

    // Wallet state update frequency. In none, no updates will be run in the background.
    pub wallet_updater_frequency_sec: Option<u32>,

    /// Electrum nodes for secondary coins
    /// Key: <coin>_[main|test]_[1|2]
    /// Value: url
    pub swap_electrumx_addr: Option<BTreeMap<String,String>>,
}

pub const WALLET713_CONFIG_HELP: &str =
"#########################################
### WALLET 713 CONFIGURATION          ###
#########################################

# Blockcahin to use: 'Mainnet' or 'Floonet'
# chain = \"Floonet\"

# Path for mwc713 wallet data
# wallet713_data_path = \"wallet713_data\"

# Path to the keybase binary
# keybase_binary = \"keybase\"

# MWC MQS connection settings. By default mwc713 using thhis method for communication.
# mwcmqs_domain = \"mqs.mwc.mw\"
# mwcmqs_port = 443

# The address to bind to for tor socks 5 proxy. By default this is set to 127.0.0.1:59051
# socks_addr = \"127.0.0.1:59051\"

# MWC MQS/GrinBox address defive index. Every new index will give you a new address that will be used for
# communication with message queue
# grinbox_address_index = 0

# MWC node connection URI. Please make sure that you are connecting to the node from correct network.
# mwc_node_uri = \"https://mwc713.floonet.mwc.mw\"

# MWC node secret
# mwc_node_secret = \"11ne3EAUtOXVKwhxm84U\"

# Start Message Queue listener automatically if wallet password was provided at start.
# grinbox_listener_auto_start = true

# Start KeyBase listener automatically if wallet password was provided at start.
# keybase_listener_auto_start = true

# Specify maximum amount in nano MWC if you want this wallet automatically accept invoices.
# Example for 5 MWCs:  max_auto_accept_invoice = 50000000000
# Note! Change it if you really understand what you are going!
# max_auto_accept_invoice =

# KetBase TTL period
# default_keybase_ttl = \"24h\"

# Enable Owner API for this wallet. See for details: https://github.com/mwcproject/mwc713/blob/master/docs/API_documentation.md
# owner_api = false

# Owner API listening address. If you want accept connections from
# the Internet, please make it \"0.0.0.0:13415\"
# owner_api_address = \"127.0.0.1:13415\"

# Owner API secret. REST API call required basic authorization with this secret (user: mwc).
# owner_api_secret = \"my_secret_password\"

# Include the foreign API endpoints on the same port as the owner
# API. Useful for networking environments like AWS ECS that make
# it difficult to access multiple ports on a single service.
# owner_api_include_foreign = false

# Enable Foreign API for this wallet. See for details: https://github.com/mwcproject/mwc713/blob/master/docs/API_documentation.md
# Note! Use this setting if you disable Owner API. Otherwise concider to use 'owner_api_include_foreign' setting
# foreign_api = false

# Foreign API listening address. If you want accept connections from
# the Internet, please make it \"0.0.0.0:13416\"
# foreign_api_address = \"127.0.0.1:13416\"

# Foreign API secret. REST API call required basic authorization with this secret (user: mwc).
# foreign_api_secret = \"my_secret_password\"

# Disable logging history of your mwc713 commands. Recommended for stronger security.
# Also you can disable history with command line argument '--disable-history'
# disable_history = false


# If enabled both tls_certificate_file and tls_certificate_key, TSL will be applicable to all rest API
# Paths to TLS certificate files:
# tls_certificate_file = \"path to TLS certificate file\"
# tls_certificate_key = \"path to TLS certificate private key file\"

# Wallet state update frequency. In none, no updates will be run in the background.
# If will be set, will run 'sync' command with defined time interval
# wallet_updater_frequency_sec =

# Electrum X servers that are used for Atomic Swap operations. Each Secondary Currency need
# its own dedicated Electrum X instance. We highly advise to use your own instance, instead of
# using those community servers.
# For every secondary currency expected 4 instances:
# mainnet primary, mainnet secondary, testnet primary, testnet secondary,
# Key: <coin>_[main|test]_[1|2]
# value: URI

# [swap_electrumx_addr]
# bch_main_1 = \"bch.main1.swap.mwc.mw:8000\"
# bch_main_2 = \"bch.main2.swap.mwc.mw:8000\"
# bch_test_1 = \"bch.test1.swap.mwc.mw:8000\"
# bch_test_2 = \"bch.test2.swap.mwc.mw:8000\"
# btc_main_1 = \"btc.main1.swap.mwc.mw:8000\"
# btc_main_2 = \"btc.main2.swap.mwc.mw:8000\"
# btc_test_1 = \"btc.test1.swap.mwc.mw:8000\"
# btc_test_2 = \"btc.test1.swap.mwc.mw:8000\"

";


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
            mwcmq_port: None,
            mwcmqs_domain: None,
            mwcmqs_port: None,
            socks_addr: None,
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
            wallet_updater_frequency_sec: None,
            swap_electrumx_addr: Some(
                [
                    ("btc_main_1", "btc.main1.swap.mwc.mw:8000"),
                    ("btc_main_2", "btc.main2.swap.mwc.mw:8000"),
                    ("btc_test_1", "btc.test1.swap.mwc.mw:8000"),
                    ("btc_test_2", "btc.test2.swap.mwc.mw:8000"),
                    ("bch_main_1", "bch.main1.swap.mwc.mw:8000"),
                    ("bch_main_2", "bch.main2.swap.mwc.mw:8000"),
                    ("bch_test_1", "bch.test1.swap.mwc.mw:8000"),
                    ("bch_test_2", "bch.test1.swap.mwc.mw:8000"),
                ].iter().cloned()
                    .map(|i| (i.0.to_string(), i.1.to_string()) )
                    .collect::<BTreeMap<String,String>>()
            )
        }
    }

    #[cfg(not(target_os = "android"))]
    fn get_config_path(config_path: Option<&str>, chain: &ChainTypes) -> Result<String,Error> {
        let default_path_buf = Wallet713Config::default_config_path(chain)?;
        let default_path = default_path_buf.to_str().unwrap();
        let config_path = config_path.unwrap_or(default_path);
        Ok(String::from(config_path))
    }
    #[cfg(target_os = "android")]
    fn get_config_path(config_path: Option<&str>, _chain: &ChainTypes) -> Result<String,Error> {
        Ok(String::from(config_path.expect("Please specify --config parameter") ))
    }

    pub fn exists(config_path: Option<&str>, chain: &ChainTypes) -> Result<bool, Error> {
        let config_path = Self::get_config_path(config_path, chain)?;
        Ok(Path::new(&config_path).exists())
    }

    pub fn from_file(
        config_path: Option<&str>,
        chain: &ChainTypes,
    ) -> Result<Wallet713Config, Error> {
        let config_path = Self::get_config_path(config_path, chain)?;
        let mut file = File::open(&config_path)?;
        let mut toml_str = String::new();
        file.read_to_string(&mut toml_str)?;
        let mut config: Wallet713Config = toml::from_str(&toml_str[..])?;
        config.config_home = Some(config_path);
        Ok(config)
    }

    #[cfg(not(target_os = "android"))]
    pub fn default_config_path(chain: &ChainTypes) -> Result<PathBuf, Error> {
        let mut path = Wallet713Config::default_home_path(chain)?;
        path.push(WALLET713_DEFAULT_CONFIG_FILENAME);
        Ok(path)
    }

    #[cfg(not(target_os = "android"))]
    pub fn default_home_path(chain: &ChainTypes) -> Result<PathBuf, Error> {
        // Desktop OS case. Home dir does exist
        #[cfg(not(target_os = "android"))]
        let mut path = match dirs::home_dir() {
            Some(home) => home,
            None => std::env::current_dir()?,
        };

        // Android doesn't have Home dir. binary dir will be used instead of home dir
        #[cfg(target_os = "android")]
            panic!("Home path doesn't exist under Android");

        path.push(WALLET713_HOME);
        path.push(chain.shortname());
        std::fs::create_dir_all(path.as_path())?;
        Ok(path)
    }

    pub fn to_file(&mut self, config_path: Option<&str>) -> Result<(), Error> {
        let config_path = Self::get_config_path(config_path, &self.chain)?;
        let toml_str = toml::to_string(&self)?;
        let mut f = File::create(&config_path)?;
        f.write_all((String::from(WALLET713_CONFIG_HELP) + &toml_str).as_bytes())?;
        self.config_home = Some(config_path);
        Ok(())
    }

    pub fn get_socks_addr(&self) -> String {
        self.socks_addr.clone().unwrap_or("127.0.0.1:59051".to_string())
    }

    pub fn get_mwcmqs_address(&self, address_public_key: &PublicKey) -> Result<MWCMQSAddress, Error> {
        Ok(MWCMQSAddress::new(
            ProvableAddress::from_pub_key(&address_public_key),
            Some(self.mwcmqs_domain()),
            self.mwcmqs_port,
        ))
    }

    #[cfg(not(target_os = "android"))]
    pub fn disable_history(&self) -> bool {
        self.disable_history.unwrap_or(false)
    }

    pub fn mwcmqs_domain(&self) -> String {
        self.mwcmqs_domain.clone().unwrap_or("mqs.mwc.mw".to_string())
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
        self.grinbox_listener_auto_start.unwrap_or(true)
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

    pub fn get_mqs_config(&self) -> MQSConfig {
        grin_wallet_config::MQSConfig {
            mwcmqs_domain: self.mwcmqs_domain.clone().unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
            mwcmqs_port: self.mwcmqs_port.clone().unwrap_or(DEFAULT_MWCMQS_PORT),
        }
    }

    pub fn get_wallet_data_dir(&self) -> String {
        let mut top_level_dir = self.get_top_level_directory().unwrap();
        if top_level_dir.len() == 0 {
            top_level_dir = std::env::current_dir().unwrap().display().to_string();
        }
        let wallet_data_dir = top_level_dir + "/" + &self.get_wallet_data_directory().unwrap();

        absolute_path(wallet_data_dir).unwrap().into_os_string().into_string().unwrap()
    }


    pub fn get_tor_config(&self) -> TorConfig {
        let mut tor_config = grin_wallet_config::TorConfig::default();
        tor_config.socks_running = true;
        tor_config.socks_proxy_addr = self.get_socks_addr();
        tor_config.send_config_dir = self.get_wallet_data_dir();
        tor_config
    }

    pub fn get_tls_config(&self, print_message: bool) -> Option<grin_api::TLSConfig> {
        if self.is_tls_enabled() {
            if print_message {
                cli_message!( "TLS is enabled. Wallet will use secure connection for Rest API" );
            }
            Some(grin_api::TLSConfig::new(self.tls_certificate_file.clone().unwrap(),
                                          self.tls_certificate_key.clone().unwrap()))
        } else {
            if !self.foreign_api_address().starts_with("127.0.0.1:") && print_message {
                cli_message!("WARNING: TLS configuration is not set. Non-secure HTTP connection will be used. It is recommended to use secure TLS connection.");
            }
            None
        }
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

fn absolute_path<P>(path: P) -> io::Result<PathBuf>
    where
        P: AsRef<Path>,
{
    use path_clean::PathClean;

    let path = path.as_ref();
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    }.clean();

    Ok(absolute_path)
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
