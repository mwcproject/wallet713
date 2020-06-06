#[macro_use]
extern crate serde_derive;
extern crate prettytable;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate blake2_rfc;
extern crate path_clean;
extern crate chrono;
extern crate ansi_term;
extern crate colored;
extern crate failure;
extern crate futures;
extern crate rustls;
extern crate mime;
extern crate parking_lot;
extern crate rand;
extern crate ring;
#[cfg(not(target_os = "android"))]
extern crate rpassword;
#[cfg(not(target_os = "android"))]
extern crate rustyline;
extern crate serde;
extern crate sha2;
extern crate tokio;
extern crate url;
extern crate uuid;
extern crate ws;
extern crate semver;
extern crate commands;
extern crate enquote;

extern crate grin_api;
extern crate grin_core;
extern crate grin_keychain;
extern crate grin_store;
extern crate grin_util;
extern crate grin_p2p;
extern crate grin_wallet_impls;
#[macro_use]
extern crate grin_wallet_libwallet;
extern crate grin_wallet_controller;
extern crate grin_wallet_util;

use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use std::{env, thread};
#[cfg(not(target_os = "android"))]
use std::borrow::Cow::{self, Borrowed, Owned};
use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::io::{Read, Write, BufReader};
use std::path::{Path, PathBuf};
use grin_core::core::Transaction;
use grin_core::ser;

use grin_util::from_hex;
use grin_util::ZeroingString;


use clap::{App, Arg, ArgMatches, SubCommand};
use colored::*;
use grin_core::core;
use grin_core::libtx::tx_fee;
use grin_core::global;
use grin_core::global::{set_mining_mode, ChainTypes};
#[cfg(not(target_os = "android"))]
use rustyline::completion::{Completer, FilenameCompleter, Pair};
#[cfg(not(target_os = "android"))]
use rustyline::config::OutputStreamType;
#[cfg(not(target_os = "android"))]
use rustyline::error::ReadlineError;
#[cfg(not(target_os = "android"))]
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
#[cfg(not(target_os = "android"))]
use rustyline::hint::Hinter;
#[cfg(not(target_os = "android"))]
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper};
use url::Url;

#[macro_use]
mod common;
mod cli;
mod contacts;
mod wallet;

use cli::Parser;
use common::config::Wallet713Config;
use common::{ErrorKind, Error, COLORED_PROMPT, Arc, Mutex};
#[cfg(not(target_os = "android"))]
use common::PROMPT;
use wallet::Wallet;
use contacts::DEFAULT_MWCMQS_PORT;
use contacts::DEFAULT_MWCMQS_DOMAIN;

use grin_wallet_libwallet::proof::tx_proof::TxProof;
use grin_wallet_libwallet::Slate;
use grin_util::secp::key::PublicKey;
use grin_wallet_impls::{MWCMQPublisher, MWCMQSubscriber, MWCMQSAddress, Publisher, Subscriber, Address, AddressType, KeybasePublisher, KeybaseSubscriber};

use contacts::{AddressBook, Backend, Contact,};

use grin_wallet_libwallet::proof::crypto::Hex;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::borrow::Borrow;
use uuid::Uuid;


use path_clean::PathClean;

#[cfg(not(target_os = "android"))]
const CLI_HISTORY_PATH: &str = ".history";

pub fn absolute_path<P>(path: P) -> io::Result<PathBuf>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }.clean();

    Ok(absolute_path)
}

fn getpassword() -> Result<String, Error> {
    let mwc_password = getenv("MWC_PASSWORD")?;
    if mwc_password.is_some() {
        return Ok(mwc_password.unwrap());
    }

    #[cfg(not(target_os = "android"))]
        return Ok(rpassword::prompt_password_stdout("Password: ").unwrap_or(String::from("")));

    // Android doesn't have terminal system functions. That is why rpassword doesn't work
    #[cfg(target_os = "android")]
        {
            print!("Password: ");
            let mut ret = String::new();
            io::stdin().read_line(&mut ret)?;
            Ok(ret)
        }
}

fn getenv(key: &str) -> Result<Option<String>, Error> {
    // Accessing an env var
    let ret = match env::var(key) {
        Ok(val) => Some(val),
        Err(_) => None,
    };
    Ok(ret)
}

fn do_config(
    args: &ArgMatches,
    chain: &ChainTypes,
    silent: bool,
    new_address_index: Option<u32>,
    config_path: Option<&str>,
) -> Result<Wallet713Config, Error> {
    let mut config;
    let mut any_matches = false;
    let exists = Wallet713Config::exists(config_path, chain)?;
    if exists {
        config = Wallet713Config::from_file(config_path, chain)?;
    } else {
        config = Wallet713Config::default(chain);
        any_matches = true;
    }

    if let Some(data_path) = args.value_of("data-path") {
        config.wallet713_data_path = data_path.to_string();
        any_matches = true;
    }

    if let Some(domain) = args.value_of("domain") {
        config.mwcmq_domain = Some(domain.to_string());
        any_matches = true;
    }

    if let Some(port) = args.value_of("port") {
        let port = u16::from_str_radix(port, 10).map_err(|_| ErrorKind::NumberParsingError)?;
        config.mwcmq_port = Some(port);
        any_matches = true;
    }

    if let Some(node_uri) = args.value_of("node-uri") {
        config.mwc_node_uri = Some(node_uri.to_string());
        any_matches = true;
    }

    if let Some(node_secret) = args.value_of("node-secret") {
        config.mwc_node_secret = Some(node_secret.to_string());
        any_matches = true;
    }

    if new_address_index.is_some() {
        config.grinbox_address_index = new_address_index;
        any_matches = true;
    }

    if any_matches {
        config.to_file(config_path)?;
    }

    if !any_matches && !silent {
        cli_message!("{}", config);
    }

    Ok(config)
}

fn do_contacts(args: &ArgMatches, address_book: Arc<Mutex<AddressBook>>) -> Result<(), Error> {
    let mut address_book = address_book.lock();
    if let Some(add_args) = args.subcommand_matches("add") {
        let name = add_args.value_of("name").expect("missing argument: name");
        let address = add_args
            .value_of("address")
            .expect("missing argument: address");

        // try parse as a general address and fallback to mwcmqs address
        let contact_address = Address::parse(address);
        let contact_address: Result<Box<dyn Address>, Error> = match contact_address {
            Ok(address) => Ok(address),
            Err(e) => {
                Ok(Box::new(MWCMQSAddress::from_str(address).map_err(|_| e)?) as Box<dyn Address>)
            }
        };

        let contact = Contact::new(name, contact_address?)?;
        address_book.add_contact(&contact)?;
    } else if let Some(add_args) = args.subcommand_matches("remove") {
        let name = add_args.value_of("name").unwrap();
        address_book.remove_contact(name)?;
    } else {
        let contacts: Vec<()> = address_book
            .contacts()
            .map(|contact| {
                cli_message!("@{} = {}", contact.get_name(), contact.get_address());
                ()
            })
            .collect();

        if contacts.len() == 0 {
            cli_message!(
                "your contact list is empty. consider using `contacts add` to add a new contact."
            );
        }
    }
    Ok(())
}

const WELCOME_FOOTER: &str = r#"Use `help` to see available commands
"#;

fn welcome(args: &ArgMatches) -> Result<Wallet713Config, Error> {
    let chain: ChainTypes = match args.is_present("floonet") {
        true => ChainTypes::Floonet,
        false => ChainTypes::Mainnet,
    };

    let config = do_config(args, &chain, true, None, args.value_of("config-path"))?;
    set_mining_mode(config.chain.clone());

    Ok(config)
}


fn start_mwcmqs_listener(
    config: &Wallet713Config,
    wallet: Arc<Mutex<Wallet>>,
) -> Result<(MWCMQPublisher, MWCMQSubscriber), Error> {
    // make sure wallet is not locked, if it is try to unlock with no passphrase
    {
        if wallet.lock().is_locked() {
            return Err(ErrorKind::WalletIsLocked)?;
        }
    }

    println!("starting mwcmqs listener...");

    let res = grin_wallet_controller::controller::start_mwcmqs_listener(
        wallet.lock().get_wallet_instance()?,
        grin_wallet_config::MQSConfig {
            mwcmqs_domain: config.mwcmqs_domain.clone().unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
            mwcmqs_port: config.mwcmqs_port.clone().unwrap_or(DEFAULT_MWCMQS_PORT),
        },
        config.grinbox_address_index.clone().unwrap_or(0),
        false,
        Arc::new(Mutex::new(None)),
        false,
    )?;

    Ok(res)
}

fn start_tor_listener(
    config: &Wallet713Config,
    wallet: Arc<Mutex<Wallet>>,
) -> Result<std::sync::Arc<std::sync::Mutex<u32>>, Error> {
    let keychain_mask = Arc::new(Mutex::new(None));

    let addr = config.foreign_api_address().clone();
    let mutex = std::sync::Arc::new(std::sync::Mutex::new(1));
    let mutex_clone = mutex.clone();

    thread::Builder::new()
            .name("tor_listener".to_string())
            .spawn(move || {
                let winst = wallet.lock().get_wallet_instance().unwrap();
                let onion_address = grin_wallet_controller::controller::get_tor_address(winst.clone(), keychain_mask.clone()).unwrap();
                let p = grin_wallet_controller::controller::init_tor_listener(winst,
                            keychain_mask, &addr);

                let _ = match p {
                     Ok(p) => {
                        cli_message!("tor listener started for [http://{}.onion]", onion_address);
                        for _ in 1..2_000_000_000 {
                            std::thread::sleep(std::time::Duration::from_millis(30));
                            let val = mutex_clone.lock().unwrap();
                            if *val == 0 { break; }
                        }

                        Some(p)
                    },
                    Err(e) => { cli_message!("error starting tor: {:?}", e); None},
                };
                cli_message!("Tor listener has stopped.");

            })?;
    Ok(mutex)
}

fn start_keybase_listener(
    config: &Wallet713Config,
    wallet: Arc<Mutex<Wallet>>,
) -> Result<(KeybasePublisher, KeybaseSubscriber), Error> {
    // make sure wallet is not locked, if it is try to unlock with no passphrase
    {
        if wallet.lock().is_locked() {
            return Err(ErrorKind::WalletIsLocked)?;
        }
    }

    cli_message!("starting keybase listener...");

    let keychain_mask = Arc::new(Mutex::new(None));
    let res = grin_wallet_controller::controller::start_keybase_listener(
        wallet.lock().get_wallet_instance()?,
        config.default_keybase_ttl.clone(),
        config.keybase_binary.clone(),
        false,
        keychain_mask,
        false)?;

    Ok(res)
}

fn start_wallet_api(
    config: &Wallet713Config,
    wallet: Arc<Mutex<Wallet>>,
) -> Result<(), Error> {
    if wallet.lock().is_locked() {
        return Ok(());
    }

    if config.owner_api() || config.foreign_api() {
        let tls_config: Option<grin_api::TLSConfig> = if config.is_tls_enabled() {
            cli_message!( "TLS is enabled. Wallet will use secure connection for Rest API" );
            Some( grin_api::TLSConfig::new(config.tls_certificate_file.clone().unwrap(),
                                           config.tls_certificate_key.clone().unwrap() ) )
        }
        else {
            cli_message!("{}: TLS configuration is not set, non secure HTTP connection will be used. It is recommended to use secure TLS connection.",
                        "WARNING".bright_yellow() );
            None
        };

        if config.owner_api.unwrap_or(false) {
            cli_message!(
                         "starting listener for owner api on [{}]",
                         config.owner_api_address().bright_green()
                     );
            if config.owner_api_secret.is_none() {
                cli_message!(
                             "{}: no api secret for owner api, it is recommended to set one.",
                             "WARNING".bright_yellow()
                         );
            }

            let wallet_instance = wallet.lock().get_wallet_instance()?;
            let addr = config.owner_api_address();
            let owner_api_secret = config.owner_api_secret.clone();
            let tls_config = tls_config.clone();
            let owner_api_include_foreign = config.owner_api_include_foreign.clone();

            thread::Builder::new()
                .name("owner_listener".to_string())
                .spawn(move || {
                    if let Err(e) = grin_wallet_controller::controller::owner_listener(
                        wallet_instance,
                        Arc::new(Mutex::new(None)),
                        &addr,
                        owner_api_secret,
                        tls_config,
                        owner_api_include_foreign,
                        None)
                    {
                        cli_message!( "{}: Owner API Listener failed, {}", e, "ERROR".bright_red() );
                    }
                })?;
        }

        if config.foreign_api.unwrap_or(false) {
            cli_message!(
                         "starting listener for foreign api on [{}]",
                         config.foreign_api_address().bright_green()
                     );
            if config.foreign_api_secret.is_some() {
                cli_message!(
                             "{}: setting the foreign_api_secret will prevent mwc-wallet from sending to this wallet because it doesn't support basic auth. mwc-qt-wallet and mwc713 support it and sender need to be aware about that.",
                             "WARNING".bright_yellow()
                         );
            }

            let wallet_instance = wallet.lock().get_wallet_instance()?;
            let foreign_api_address = config.foreign_api_address();
            let tls_config = tls_config.clone();

            thread::Builder::new()
                .name("foreign_listener".to_string())
                .spawn(move || {
                    if let Err(e) = grin_wallet_controller::controller::foreign_listener(
                        wallet_instance,
                        Arc::new(Mutex::new(None)),
                        &foreign_api_address,
                        tls_config,
                        false)
                    {
                        cli_message!( "{}: Foreign API Listener failed, {}", e, "ERROR".bright_red() );
                    }
                })?;
        }
    }

    Ok(())
}

#[cfg(not(target_os = "android"))]
struct EditorHelper(FilenameCompleter, MatchingBracketHighlighter);

#[cfg(not(target_os = "android"))]
impl Completer for EditorHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> std::result::Result<(usize, Vec<Pair>), ReadlineError> {
        self.0.complete(line, pos, ctx)
    }
}

#[cfg(not(target_os = "android"))]
impl Hinter for EditorHelper {
    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

#[cfg(not(target_os = "android"))]
impl Highlighter for EditorHelper {
    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.1.highlight(line, pos)
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(&'s self, prompt: &'p str, default: bool) -> Cow<'b, str> {
        if default {
            Borrowed(COLORED_PROMPT)
        } else {
            Borrowed(prompt)
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.1.highlight_char(line, pos)
    }
}

fn kill_tor_if_exists() {
    println!("killing tor");
}

#[cfg(not(target_os = "android"))]
impl Helper for EditorHelper {}

fn main() {
    enable_ansi_support();
    kill_tor_if_exists();

    let matches = App::new("mwc713")
        .version(crate_version!())
        .arg(Arg::from_usage("[config-path] -c, --config=<config-path> 'the path to the config file'"))
        .arg(Arg::from_usage("[log-config-path] -l, --log-config-path=<log-config-path> 'the path to the log config file'"))
        .arg(Arg::from_usage("[account] -a, --account=<account> 'the account to use'"))
        .arg(Arg::from_usage("[disable-history] -z, --disable-history 'disable adding commands to the history'"))
        .arg(Arg::from_usage("[passphrase] -p, --passphrase=<passphrase> 'the passphrase to use'"))
        .arg(Arg::from_usage("[daemon] -d, --daemon 'run daemon'"))
        .arg(Arg::from_usage("[floonet] -f, --floonet 'use floonet'"))
        .arg(Arg::from_usage("[ready-phrase] -r, --ready-phrase=<phrase> 'use additional ready phrase printed when wallet ready to read input'"))
        .subcommand(SubCommand::with_name("init").about("initializes the wallet"))
        .subcommand(
            SubCommand::with_name("recover")
                .about("recover wallet from mnemonic or displays the current mnemonic")
                .arg(Arg::from_usage("[words] -m, --mnemonic=<words>... 'the seed mnemonic'"))
        )
        .subcommand(SubCommand::with_name("state").about("print wallet initialization state and exit"))
        .get_matches();

    let disable_history = matches.is_present("disable-history");

    let mut config: Wallet713Config = welcome(&matches ).unwrap_or_else(|e| {
        panic!(
            "{}: could not read or create config! {}",
            "ERROR".bright_red(),
            e
        );
    });

    if disable_history {
        config.disable_history = Some(true);
    }

    let data_path_buf = config.get_data_path().unwrap();
    let data_path = data_path_buf.to_str().unwrap();

    let address_book_backend =
        Backend::new(data_path).expect("could not create address book backend!");
    let address_book = AddressBook::new(Box::new(address_book_backend))
        .expect("could not create an address book!");
    let address_book = Arc::new(Mutex::new(address_book));

    println!("{}", format!("\nWelcome to wallet713 for MWC v{}\n", crate_version!()).bright_yellow().bold());

    let wallet = Arc::new(Mutex::new(Wallet::new() ));

    let mut keybase_broker: Option<(KeybasePublisher, KeybaseSubscriber)> = None;
    let mut mwcmqs_broker: Option<(MWCMQPublisher, MWCMQSubscriber)> = None;
    let mut tor_state: Option<std::sync::Arc<std::sync::Mutex<u32>>> = Some(std::sync::Arc::new(std::sync::Mutex::new(0)));
    let mut tor_running: bool = false;


    let has_seed = Wallet::seed_exists(&config);

    // TODO: print something nicer for the user
    if matches.subcommand_matches("state").is_some() {
        match has_seed {
            true => println!("Initialized"),
            false => println!("Uninitialized")
        };
        std::process::exit(0);
    }

    if !has_seed {
        let mut line = String::new();

        if matches.subcommand_matches("init").is_some() {
            line = "init".to_string();
        }
        if matches.subcommand_matches("recover").is_some() {
            line = "recover".to_string();
        }
        if line == String::new() {
            println!("{}", "Please choose an option".bright_green().bold());
            println!(" 1) {} a new wallet", "init".bold());
            println!(" 2) {} from mnemonic", "recover".bold());
            println!(" 3) {}", "exit".bold());
            println!();
            print!("{}", "> ".cyan());
            io::stdout().flush().unwrap();

            if io::stdin().read_line(&mut line).unwrap() == 0 {
                println!("{}: invalid option", "ERROR".bright_red());
                std::process::exit(1);
            }

            println!();
        }

        let passphrase = if matches.is_present("passphrase") {
            matches.value_of("passphrase").unwrap()
        } else {
            ""
        };

        let line = line.trim();
        let mut out_is_safe = false;
        match line {
            "1" | "init" | "" => {
                println!("{}", "Initialising a new wallet".bold());
                println!();
                println!("Set an optional password to secure your wallet with. Leave blank for no password.");
                println!();
                let cmd = format!("init -p {}", &passphrase);
                if let Err(err) = do_command(&cmd, &mut config, wallet.clone(), address_book.clone(), &mut keybase_broker,  &mut mwcmqs_broker, &mut out_is_safe, &mut tor_state, &mut tor_running) {
                    println!("{}: {}", "ERROR".bright_red(), err);
                    std::process::exit(1);
                }
            },
            "2" | "recover" | "restore" => {
                println!("{}", "Recovering from mnemonic".bold());
                print!("Mnemonic: ");
                io::stdout().flush().unwrap();
                let mut mnemonic = String::new();

                if let Some(recover) = matches.subcommand_matches("recover") {
                    if recover.is_present("words") {
                        mnemonic = matches.subcommand_matches("recover").unwrap().value_of("words").unwrap().to_string();
                    }
                } else {
                    if io::stdin().read_line(&mut mnemonic).unwrap() == 0 {
                        println!("{}: invalid mnemonic", "ERROR".bright_red());
                        std::process::exit(1);
                    }
                    mnemonic = mnemonic.trim().to_string();
                };

                println!();
                println!("Set an optional password to secure your wallet with. Leave blank for no password.");
                println!();
                // TODO: refactor this
                let cmd = format!("recover -m {} -p {}", mnemonic, &passphrase);
                if let Err(err) = do_command(&cmd, &mut config, wallet.clone(), address_book.clone(), &mut keybase_broker, &mut mwcmqs_broker, &mut out_is_safe, &mut tor_state, &mut tor_running) {
                    println!("{}: {}", "ERROR".bright_red(), err);
                    std::process::exit(1);
                }
            },
            "3" | "exit" => {
                return;
            },
            _ => {
                println!("{}: invalid option", "ERROR".bright_red());
                std::process::exit(1);
            },
        }

        println!();
    } else {
        if matches.subcommand_matches("init").is_some() {
            println!("Seed file already exists! Not initializing");
            std::process::exit(1);
        }
        if matches.subcommand_matches("recover").is_some() {
            println!("Seed file already exists! Not recovering");
            std::process::exit(1);
        }
    }

    if wallet.lock().is_locked() {
        let account = matches.value_of("account").unwrap_or("default").to_string();
        let has_wallet = if matches.is_present("passphrase") {
            let passphrase = password_prompt(matches.value_of("passphrase"));
            let result = wallet.lock().unlock(&config, &account, grin_util::ZeroingString::from(passphrase.as_str()));
            if let Err(ref err) = result {
                println!("{}: {}", "ERROR".bright_red(), err);
                std::process::exit(1);
            }
            result.is_ok()
        }
        else {
            wallet.lock().unlock(&config, &account, grin_util::ZeroingString::from("")).is_ok()
        };

        if has_wallet {
            if let Err(e) = derive_address_key(&mut config, wallet.clone()) {
                cli_message!("{}: {}", "ERROR".bright_red(), e);
            }
            if let Err(e) = start_wallet_api(&config, wallet.clone()) {
                cli_message!("{}: {}", "ERROR".bright_red(), e);
            }
        }
        else {
            println!(
                "{}",
                "Unlock your existing wallet or type `init` to initiate a new one"
                    .bright_blue()
                    .bold()
            );
        }
    }

    println!("{}", WELCOME_FOOTER.bright_blue());

    if config.grinbox_listener_auto_start() {
        let result = start_mwcmqs_listener(&config, wallet.clone());
        match result {
            Err(e) => cli_message!("{}: {}", "ERROR".bright_red(), e),
            Ok((publisher, subscriber)) => {
                mwcmqs_broker = Some((publisher, subscriber));
            },
        }

    }

    if config.keybase_listener_auto_start() {
        let result = start_keybase_listener(&config, wallet.clone());
        match result {
            Err(e) => cli_message!("{}: {}", "ERROR".bright_red(), e),
            Ok((publisher, subscriber)) => {
                keybase_broker = Some((publisher, subscriber));
            },
        }
    }

    #[cfg(not(target_os = "android"))]
        let mut rl = {
        let editor_config = Config::builder()
            .history_ignore_space(true)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .output_stream(OutputStreamType::Stdout)
            .build();
        let mut rl = Editor::with_config(editor_config);
        rl.set_helper(Some(EditorHelper(
            FilenameCompleter::new(),
            MatchingBracketHighlighter::new(),
        )));
        rl
    };

    #[cfg(not(target_os = "android"))]
        let wallet713_home_path_buf = Wallet713Config::default_home_path(&config.chain).unwrap();
    #[cfg(not(target_os = "android"))]
        let wallet713_home_path = wallet713_home_path_buf.to_str().unwrap();

    #[cfg(not(target_os = "android"))]
        {
            if let Some(path) = Path::new(wallet713_home_path)
                .join(CLI_HISTORY_PATH)
                .to_str()
            {
                let _ = rl.load_history(path).is_ok();
            }
        }

    let prompt_plus = matches.value_of("ready-phrase").unwrap_or("").to_string();

    loop {
        if !prompt_plus.is_empty() {
            println!("{}", prompt_plus);
        }

        #[cfg(not(target_os = "android"))]
            let command = match rl.readline(PROMPT) {
            Ok(command) => command.trim().to_string(),
            Err(e) => {
                cli_message!("Error: Unable to read input, {}", e);
                break;
            }
        };

        #[cfg(target_os = "android")]
            let command = {
                let mut cmd = String::new();
                if io::stdin().read_line(&mut cmd).unwrap() > 0 {
                    cmd.trim().to_string()
                }
                else {
                    continue;
                }
            };

        if command == "exit" {
            let mut ptr = tor_state.as_ref().unwrap().lock().unwrap();
            if *ptr != 0 {
                cli_message!("Stopping TOR listener...");
                *ptr = 0;
            }
            if mwcmqs_broker.is_some() {
                let mut mqs = mwcmqs_broker.unwrap();
                if mqs.1.is_running() {
                    mqs.1.stop();
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(100));

            break;
        }

        let mut out_is_safe = false;
        let result = do_command(
            &command,
            &mut config,
            wallet.clone(),
            address_book.clone(),
            &mut keybase_broker,
            &mut mwcmqs_broker,
            &mut out_is_safe,
            &mut tor_state,
            &mut tor_running,
        );

        if let Err(err) = result {
            cli_message!("Error: {}", err);
        }

        #[cfg(not(target_os = "android"))]
            {
                if out_is_safe {
                    if config.disable_history() != true {
                        rl.add_history_entry(command);
                    }
                }
            }
    }

    #[cfg(not(target_os = "android"))]
        {
            if let Some(path) = Path::new(wallet713_home_path)
                .join(CLI_HISTORY_PATH)
                .to_str()
            {
                let _ = rl.save_history(path).is_ok();
            }
        }
}

fn derive_address_key(
    config: &mut Wallet713Config,
    wallet: Arc<Mutex<Wallet>>,
) -> Result<(), Error> {
    let index = config.grinbox_address_index();
    let key = wallet.lock().derive_address_key(index)?;
    config.grinbox_address_key = Some(key);
    show_address(config, false)?;
    Ok(())
}


fn show_address(config: &Wallet713Config, include_index: bool) -> Result<(), Error> {
    println!(
        "{}: {}",
        "Your mwcmqs address".bright_yellow(),
        config.get_mwcmqs_address()?.get_stripped().bright_green()
    );
    if include_index {
        println!(
            "Derived with index [{}]",
            config.grinbox_address_index().to_string().bright_blue()
        );
    }
    Ok(())
}

fn password_prompt(opt: Option<&str>) -> String {
    opt.map(String::from).unwrap_or_else(|| {
        getpassword().unwrap()
    })
}

fn proof_ok(
    sender: Option<String>,
    receiver: String,
    amount: u64,
    outputs: Vec<String>,
    kernel: String,
) {
    let sender_message = sender
        .as_ref()
        .map(|s| format!(" from [{}]", s.bright_green()))
        .unwrap_or(String::new());

    println!(
        "this file proves that [{}] MWCs was sent to [{}]{}",
        core::amount_to_hr_string(amount, false).bright_green(),
        receiver.bright_green(),
        sender_message
    );

    if sender.is_none() {
        println!(
            "{}: this proof does not prove which address sent the funds, only which received it",
            "WARNING".bright_yellow()
        );
    }

    println!("\noutputs:");
    if global::is_mainnet() {
        for output in outputs {
            println!("   {}: https://explorer.mwc.mw/#o{}", output.bright_magenta(), output);
        }
        println!("kernel:");
        println!("   {}: https://explorer.mwc.mw/#k{}", kernel.bright_magenta(), kernel);
    } else {
        for output in outputs {
            println!("   {}: https://explorer.floonet.mwc.mw/#o{}", output.bright_magenta(), output);
        }
        println!("kernel:");
        println!("   {}: https://explorer.floonet.mwc.mw/#k{}", kernel.bright_magenta(), kernel);
    }
    println!("\n{}: this proof should only be considered valid if the kernel is actually on-chain with sufficient confirmations", "WARNING".bright_yellow());
    println!("please use a mwc block explorer to verify this is the case.");
}

fn do_command(
    command: &str,
    config: &mut Wallet713Config,
    wallet: Arc<Mutex<Wallet>>,
    address_book: Arc<Mutex<AddressBook>>,
    keybase_broker: &mut Option<(KeybasePublisher, KeybaseSubscriber)>,
    mwcmqs_broker: &mut Option<(MWCMQPublisher, MWCMQSubscriber)>,
    out_is_safe: &mut bool,
    tor_state: &mut Option<std::sync::Arc<std::sync::Mutex<u32>>>,
    tor_running: &mut bool,
) -> Result<(), Error> {
    *out_is_safe = true;

    #[cfg(not(target_os = "android"))]
        let home_dir = dirs::home_dir()
        .map(|p| p.to_str().unwrap().to_string())
        .unwrap_or("~".to_string());

    #[cfg(target_os = "android")]
        let home_dir = std::env::current_exe() //  dirs::home_dir()
        .map(|p| { let mut p = p.clone(); p.pop();  p.to_str().unwrap().to_string()})
        .unwrap_or("~".to_string());

    let matches = Parser::parse(command)?;
    match matches.subcommand_name() {
        Some("config") => {
            let args = matches.subcommand_matches("config").unwrap();

            let new_address_index = match args.is_present("generate-address") {
                false => None,
                true => Some({
                    let index = match args.value_of("generate-address-index") {
                        Some(index) => u32::from_str_radix(index, 10)
                            .map_err(|_| ErrorKind::NumberParsingError)?,
                        None => config.grinbox_address_index() + 1,
                    };
                    config.grinbox_address_index = Some(index);
                    index
                }),
            };

            *config = do_config(
                args,
                &config.chain,
                false,
                new_address_index,
                config.config_home.as_ref().map(|x| &**x),
            )?;

            if new_address_index.is_some() {
                derive_address_key(config, wallet)?;
                cli_message!(
                    "Derived with index [{}]",
                    config.grinbox_address_index().to_string().bright_blue()
                );
            }
        }
        Some("address") => {
            show_address(config, true)?;
        }
        Some("init") => {
            *out_is_safe = false;
            if keybase_broker.is_some() {
                return Err(ErrorKind::HasListener.into());
            }
            let args = matches.subcommand_matches("init").unwrap();
            let passphrase = match args.is_present("passphrase") {
                true => password_prompt(args.value_of("passphrase")),
                false => "".to_string(),
            };
            *out_is_safe = args.value_of("passphrase").is_none();

            if passphrase.is_empty() {
                println!("{}: wallet with no passphrase.", "WARNING".bright_yellow());
            }

            let passphrase = grin_util::ZeroingString::from(passphrase);

            let seed = wallet
                .lock()
                .init(config, passphrase.clone(), true)?;

            println!("{}", "Press ENTER when you have done so".bright_green().bold());

            let mut line = String::new();
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut line).unwrap();

            {
                let mut wallet_inst = wallet.lock();
                wallet_inst.complete(seed, config, "default", passphrase, true)?;
                wallet_inst.update_tip_as_last_scanned()?;
            }
            derive_address_key(config, wallet)?;

            return Ok(());
        }
        Some("unlock") => {
            let args = matches.subcommand_matches("unlock").unwrap();
            let account = args.value_of("account").unwrap_or("default");
            let passphrase = match args.is_present("passphrase") {
                true => password_prompt(args.value_of("passphrase")),
                false => "".to_string(),
            };
            *out_is_safe = args.value_of("passphrase").is_none();

            {
                let mut w = wallet.lock();
                if !w.is_locked() {
                    return Err(ErrorKind::WalletAlreadyUnlocked.into());
                }
                w.unlock(config, account, ZeroingString::from(passphrase.as_str()))?;
            }

            derive_address_key(config, wallet.clone())?;

            start_wallet_api(config, wallet)?;

            return Ok(());
        }
        Some("accounts") => {
            wallet.lock().list_accounts()?;
        }
        Some("account") => {
            let args = matches.subcommand_matches("account").unwrap();

            let create_args = args.subcommand_matches("create");
            let switch_args = args.subcommand_matches("switch");
            let rename_args = args.subcommand_matches("rename");
            if let Some(args) = create_args {
                wallet
                    .lock()
                    .create_account(args.value_of("name").unwrap())?;
            } else if let Some(args) = switch_args {
                let account = args.value_of("name").unwrap();
                wallet.lock().switch_account(account)?;
            } else if let Some(args) = rename_args {
                let old_account = args.value_of("old_account").unwrap();
                let new_account = args.value_of("new_account").unwrap();
                wallet.lock().rename_account(old_account, new_account)?;
            }

            return Ok(());
        }
        Some("listen") => {
            let mwcmqs = matches
                .subcommand_matches("listen")
                .unwrap()
                .is_present("mwcmqs");
            let keybase = matches
                .subcommand_matches("listen")
                .unwrap()
                .is_present("keybase");
            let tor = matches
                .subcommand_matches("listen")
                .unwrap()
                .is_present("tor");
            if mwcmqs || (!keybase && !tor) {
                let is_running = match mwcmqs_broker {
                    Some((_, subscriber)) => subscriber.is_running(),
                    _ => false,
                };
                if is_running {
                    Err(ErrorKind::AlreadyListening("mwcmqs".to_string()))?
                } else {
                    let (publisher, subscriber) =
                        start_mwcmqs_listener(&config, wallet.clone())?;
                    *mwcmqs_broker = Some((publisher, subscriber));
                }
            }
            if keybase {
                let is_running = match keybase_broker {
                    Some((_, subscriber)) => subscriber.is_running(),
                    _ => false,
                };
                if is_running {
                    Err(ErrorKind::AlreadyListening("keybase".to_string()))?
                } else {
                    let (publisher, subscriber) =
                        start_keybase_listener(&config, wallet.clone())?;
                    *keybase_broker = Some((publisher, subscriber));
                }
            }
            if tor {
                if !(*tor_running) {
                    if config.foreign_api() {
                        cli_message!("starting tor listener...");
                        *tor_running = true;
                        *tor_state = Some(start_tor_listener(&config, wallet.clone())?);
                    } else {
                        return Err(ErrorKind::TORError("Foreign API must be enabled to use TOR.".to_string()))?;
                    }
                } else {
                    cli_message!("ERROR: TOR listener already started!");
                }
            }
        }
        Some("stop") => {
            let mwcmqs = matches
                .subcommand_matches("stop")
                .unwrap()
                .is_present("mwcmqs");
            let keybase = matches
                .subcommand_matches("stop")
                .unwrap()
                .is_present("keybase");
            let tor = matches
                .subcommand_matches("stop")
                .unwrap()
                .is_present("tor");

            if mwcmqs || (!keybase && !tor) {
                let is_running = match mwcmqs_broker {
                    Some((_, subscriber)) => subscriber.is_running(),
                    _ => false,
                };
                if is_running {
                    cli_message!("stopping mwcmqs listener...");
                    let mut success = false;
                    if let Some((_, subscriber)) = mwcmqs_broker {
                        success = subscriber.stop();
                    };
                    if success {
                        *mwcmqs_broker = None;
                    } else {
                        println!("{}: Could not contact mwcmqs. Network down?", "WARNING".bright_yellow());
                    }
                } else {
                    Err(ErrorKind::ClosedListener("mwcmqs".to_string()))?
                }
            }
            if keybase {
                let is_running = match keybase_broker {
                    Some((_, subscriber)) => subscriber.is_running(),
                    _ => false,
                };
                if is_running {
                    cli_message!("stopping keybase listener...");
                    if let Some((_, subscriber)) = keybase_broker {
                        subscriber.stop();
                    };
                    *keybase_broker = None;
                } else {
                    Err(ErrorKind::ClosedListener("keybase".to_string()))?
                }
            }
            if tor {
                let mut ptr = tor_state.as_ref().unwrap().lock().unwrap();
                if *ptr != 0 {
                    cli_message!("Stopping TOR listener...");
                    *ptr = 0;
                    *tor_running = false;
                } else {
                    cli_message!("ERROR: TOR listener is not running!");

                }
            }
        }
        Some("info") => {
            let args = matches.subcommand_matches("info").unwrap();

            let confirmations = args.value_of("confirmations").unwrap_or("10");
            let confirmations = u64::from_str_radix(confirmations, 10)
                .map_err(|_| ErrorKind::InvalidMinConfirmations(confirmations.to_string()))?;

            wallet.lock().info(!args.is_present("--no-refresh"), confirmations)?;
        }
        Some("txs_count") => {
            let count = wallet.lock().txs_count()?;
            cli_message!("{:?}", count);
        }
        Some("txs") => {
            let args = matches.subcommand_matches("txs").unwrap();

            // get pagination parameters default is to not do pagination when length == 0.
            let pagination_length = args.value_of("length").unwrap_or("0");
            let pagination_start = args.value_of("offset").unwrap_or("0");
            let show_full_info = args.is_present("full");
            let no_refresh = args.is_present("no-refresh");

            let tx_id: Option<u32> = match args.value_of("id") {
                Some(s) => Some(u32::from_str_radix(s, 10).map_err(|_| ErrorKind::InvalidTxIdNumber(s.to_string()))?),
                _ => None,
            };
            let tx_slate_id: Option<Uuid> = match args.value_of("txid") {
                Some(s) => Some( Uuid::parse_str(s).map_err(|_| ErrorKind::InvalidTxUuid(s.to_string()))?),
                _ => None
            };

            let pagination_length = u32::from_str_radix(pagination_length, 10)
                .map_err(|_| ErrorKind::InvalidPaginationLength(pagination_length.to_string()))?;

            let pagination_start = u32::from_str_radix(pagination_start, 10)
                .map_err(|_| ErrorKind::InvalidPaginationStart(pagination_length.to_string()))?;

            let pagination_length : Option<u32> = if pagination_length>0 {
                Some(pagination_length)
            }
            else {
                None
            };

            let pagination_start: Option<u32> = if pagination_start>0 {
                Some(pagination_start)
            }
            else {
                None
            };

            wallet.lock().txs(!no_refresh, show_full_info, pagination_start, pagination_length, tx_id, tx_slate_id )?;
        }
        Some("txs-bulk-validate") => {
            let args = matches.subcommand_matches("txs-bulk-validate").unwrap();

            let kernels_fn = args.value_of("kernels").unwrap();
            let outputs_fn = args.value_of("outputs").unwrap();
            let result_fn = args.value_of("result").unwrap();

            wallet.lock().txs_bulk_validate(kernels_fn, outputs_fn, result_fn )?;

            cli_message!("Please check results in CSV format at {}", result_fn);

        }
        Some("contacts") => {
            let arg_matches = matches.subcommand_matches("contacts").unwrap();
            do_contacts(&arg_matches, address_book.clone())?;
        }
        Some("output_count") => {
            let args = matches.subcommand_matches("output_count").unwrap();
            let show_spent = args.is_present("show-spent");
            let all_outputs = wallet.lock().all_output_count(show_spent)?;
            cli_message!("{:?}", all_outputs);
        }
        Some("outputs") => {
            let args = matches.subcommand_matches("outputs").unwrap();

            // get pagination parameters default is to not do pagination when length == 0.
            let pagination_length = args.value_of("length").unwrap_or("0");
            let pagination_start = args.value_of("offset").unwrap_or("0");
            let no_refresh = args.is_present("no-refresh");

            let pagination_length = u32::from_str_radix(pagination_length, 10)
                .map_err(|_| ErrorKind::InvalidPaginationLength(pagination_length.to_string()))?;

            let pagination_start = u32::from_str_radix(pagination_start, 10)
                .map_err(|_| ErrorKind::InvalidPaginationStart(pagination_length.to_string()))?;

            let pagination_length : Option<u32> = if pagination_length>0 {
                Some(pagination_length)
            }
            else {
                None
            };

            let pagination_start: Option<u32> = if pagination_start>0 {
                Some(pagination_start)
            }
            else {
                None
            };

            let show_spent = args.is_present("show-spent");
            wallet.lock().outputs(!no_refresh, show_spent, pagination_start, pagination_length)?;
        }
        Some("repost") => {
            let args = matches.subcommand_matches("repost").unwrap();
            let id = args.value_of("id").unwrap();
            let id = id
                .parse::<u32>()
                .map_err(|_| ErrorKind::InvalidTxId(id.to_string()))?;
            wallet.lock().repost(id, false)?;
        }
        Some("cancel") => {
            let args = matches.subcommand_matches("cancel").unwrap();
            let id = args.value_of("id").unwrap();
            let id = id
                .parse::<u32>()
                .map_err(|_| ErrorKind::InvalidTxId(id.to_string()))?;
            wallet.lock().cancel(id)?;
        }
        Some("getnextkey") => {
            let args =  matches.subcommand_matches("getnextkey").unwrap();
            let amount = args.value_of("amount").unwrap_or("0");
            let amount = amount.parse::<u64>().unwrap();

            if amount <= 0 {
                cli_message!("Error: amount greater than 0 must be specified");
            }
            else
            {
                wallet.lock().getnextkey(amount)?;
            }
        }
	Some("encryptslate") => {
		let args = matches.subcommand_matches("encryptslate").unwrap();
 		let to = args.value_of("to");
		let slate = args.value_of("slate").unwrap();
		let slate = Slate::deserialize_upgrade(&slate)?;

		if to.is_none() {
			return Err(ErrorKind::ToNotSpecified("".to_string()).into());
		}
		let to = to.unwrap();
        let mwcmqs_address = MWCMQSAddress::from_str(&to.to_string())?;

		if let Some((publisher, _)) = mwcmqs_broker {
                        let slate = publisher.encrypt_slate(&slate, mwcmqs_address.borrow())?;
			println!("slate='{}'", slate);
		} else {
            let mwcmqs_address_for_publisher = config.get_mwcmqs_address()?;
            let mwcmqs_secret_key = config.get_grinbox_secret_key()?;
            let addr_name = mwcmqs_address.get_stripped();

            let keychain_mask = Arc::new(Mutex::new(None));

            let controller = grin_wallet_controller::controller::Controller::new(
                &addr_name,
                wallet.lock().get_wallet_instance()?,
                keychain_mask,
                config.max_auto_accept_invoice,
                false,
            );

            let publisher = MWCMQPublisher::new(
                mwcmqs_address_for_publisher,
                &mwcmqs_secret_key,
                config.clone().mwcmqs_domain.unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
                config.clone().mwcmqs_port.unwrap_or(DEFAULT_MWCMQS_PORT),
                false,
                Box::new(controller.clone())
            );

            let slate = publisher.encrypt_slate(&slate, mwcmqs_address.borrow())?;
            println!("slate='{}'", slate);
		}
	}
	Some("decryptslate") => {
		let args = matches.subcommand_matches("decryptslate").unwrap();
		let slate = args.value_of("slate").unwrap();
		let public_key = config.get_grinbox_public_key()?;
		let source_address = ProvableAddress::from_pub_key(&public_key);
		let mut data = "http://example.com/?".to_string();
		data.push_str(slate);

		let url = Url::parse(&data)?;
		let mut pairs = url.query_pairs();
		let mut from = String::new();
		let mut signature = String::new();
		let mut mapmessage = String::new();

        while pairs.count()>0 {
			let next = pairs.next();
			let next = next.unwrap();
			if next.0 == "from" { from = next.1.to_string(); }
			if next.0 == "signature" { signature = next.1.to_string(); }
			if next.0 == "mapmessage" { mapmessage = next.1.to_string(); }
		}

 		if let Some((publisher, _)) = mwcmqs_broker {
            let decrypted_slate = publisher.decrypt_slate(from, mapmessage, signature, &source_address)?;
			println!("slate='{}'", decrypted_slate);
		}
        else
        {
            let mwcmqs_address = config.get_mwcmqs_address()?;
            let mwcmqs_secret_key = config.get_grinbox_secret_key()?;
            let addr_name = mwcmqs_address.get_stripped();

            let keychain_mask = Arc::new(Mutex::new(None));

            let controller = grin_wallet_controller::controller::Controller::new(
                &addr_name,
                wallet.lock().get_wallet_instance()?,
                keychain_mask,
                config.max_auto_accept_invoice,
                false,
            );

            let publisher = MWCMQPublisher::new(
                mwcmqs_address.clone(),
                &mwcmqs_secret_key,
                config.clone().mwcmqs_domain.unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
                config.clone().mwcmqs_port.unwrap_or(DEFAULT_MWCMQS_PORT),
                false,
                Box::new(controller.clone())
            );

            let decrypted_slate = publisher.decrypt_slate(from, mapmessage, signature, &source_address)?;
            println!("slate='{}'", decrypted_slate);
        }
	}
        Some("receive") => {
            let args = matches.subcommand_matches("receive").unwrap();
            let key_id = args.value_of("key_id");
            let input = args.value_of("file").unwrap();
            let rfile_param = args.value_of("recv_file");
            let mut file = File::open(input.replace("~", &home_dir))?;
            let mut slate = String::new();
            file.read_to_string(&mut slate)?;
            let mut slate = Slate::deserialize_upgrade(&slate)?;
            let mut file = File::create(&format!("{}.response", input.replace("~", &home_dir)))?;

            let output_amounts = if rfile_param.is_some() {
                let mut nvec = Vec::new();
                let rfile = File::open(rfile_param.unwrap().replace("~", &home_dir))?;
                let mut buf = BufReader::new(rfile);
                let mut done = false; // mut done: bool

                while !done {
                    let mut line = String::new();
                    let len = buf.read_line(&mut line)?;

                    if len == 0 {
                        done = true;
                    }
                    else
                    {
                        line = line.trim().to_string();
                        nvec.push(line.parse::<u64>()?);
                    }

                }
                Some(nvec)
            }
            else {
                None
            };

            let w = wallet.lock();
            // Processing with a new receive account
            w.process_sender_initiated_slate(Some(String::from("file")), &mut slate, key_id, output_amounts, None )?;
            let message = &slate.participant_data[0].message;
            let amount = core::amount_to_hr_string(slate.amount, false);
            if message.is_some() {
                cli_message!("{} received. amount = [{}], message = [{:?}]", input, amount, message.clone().unwrap());
            }
            else {
                cli_message!("{} received. amount = [{}]", input, amount);
            }
            file.write_all(serde_json::to_string(&slate)?.as_bytes())?;
            cli_message!("{}.response created successfully.", input);
        }
        Some("showpubkeys") => {
            let args = matches.subcommand_matches("showpubkeys").unwrap();
            let input = args.value_of("file").unwrap();
            let mut file = File::open(input.replace("~", &home_dir))?;
            let mut slate = String::new();
            file.read_to_string(&mut slate)?;
            let slate = Slate::deserialize_upgrade(&slate)?;
            for p in slate.participant_data {
                println!("pubkey[{}]={:?}", p.id, p.public_blind_excess);
            }
        }
        Some("finalize") => {
            let args = matches.subcommand_matches("finalize").unwrap();
            let fluff = args.is_present("fluff");
            let input = args.value_of("file").unwrap();
            let mut file = File::open(input.replace("~", &home_dir))?;
            let mut slate = String::new();
            file.read_to_string(&mut slate)?;
            let mut slate = Slate::deserialize_upgrade(&slate)?;
            wallet.lock().finalize_post_slate(&mut slate, fluff)?;
            cli_message!("{} finalized.", input);
        }
        Some("submit") => {
            let args = matches.subcommand_matches("submit").unwrap();
            let input = args.value_of("file").unwrap();
            let mut file = File::open(input.replace("~", &home_dir))?;
            let mut txn_file = String::new();
            file.read_to_string(&mut txn_file)?;
            let tx_bin = from_hex(&txn_file)?;
            let mut txn = ser::deserialize::<Transaction>(&mut &tx_bin[..], ser::ProtocolVersion(1) )?;
            let fluff = args.is_present("fluff");
            wallet.lock().submit(&mut txn, fluff)?;
        }
        Some("nodeinfo") => {
            wallet.lock().node_info()?;
        }
        Some("send") => {
            let args = matches.subcommand_matches("send").unwrap();
            let to = args.value_of("to");
            let input = args.value_of("file");
            let message = args.value_of("message").map(|s| s.to_string());
            let apisecret = args.value_of("apisecret").map(|s| s.to_string());
            let strategy = args.value_of("strategy").unwrap_or("smallest");
            if strategy != "smallest" && strategy != "all" && strategy != "custom" {
                return Err(ErrorKind::InvalidStrategy.into());
            }

            let routputs_arg = args.value_of("routputs").unwrap_or("1");
            let routputs = usize::from_str_radix(routputs_arg, 10)?;

            let outputs_arg = args.value_of("outputs");

            let output_list = if outputs_arg.is_none() {
                if strategy == "custom" {
                    return Err(ErrorKind::CustomWithNoOutputs.into());
                }
                None
            }
            else
            {
                if strategy != "custom" {
                    return Err(ErrorKind::NonCustomWithOutputs.into());
                }
                let ret: Vec<_> = outputs_arg.unwrap().split(",").collect();
                Some(ret)
            };

            let ttl_blocks = args.value_of("ttl-blocks").unwrap_or("0");
            let ttl_blocks = u64::from_str_radix(ttl_blocks, 10)
                .map_err(|_| ErrorKind::InvalidTTLBlocks(ttl_blocks.to_string()))?;

            let confirmations = args.value_of("confirmations").unwrap_or("10");
            let confirmations = u64::from_str_radix(confirmations, 10)
                .map_err(|_| ErrorKind::InvalidMinConfirmations(confirmations.to_string()))?;

            if confirmations < 1 {
                return Err(ErrorKind::ZeroConfNotAllowed.into());
            }

            let change_outputs = args.value_of("change-outputs").unwrap_or("1");
            let change_outputs = u32::from_str_radix(change_outputs, 10)
                .map_err(|_| ErrorKind::InvalidNumOutputs(change_outputs.to_string()))?;

            let version = match args.value_of("version") {
                Some(v) => Some(u16::from_str_radix(v, 10)
                    .map_err(|_| ErrorKind::InvalidSlateVersion(v.to_string()))?),
                None => None,
            };
            let fluff = args.is_present("fluff");

            let amount = args.value_of("amount").unwrap();
            let mut ntotal = 0;
            if amount == "ALL" {
                // Update from the node once. No reasons to do that twice in tthe row
                let max_available = wallet.lock().output_count(true, confirmations, output_list.clone())?;
                let total_value = wallet.lock().total_value(false, confirmations, output_list.clone())?;
                let fee = tx_fee(max_available, 1, 1, None);
                ntotal = if total_value >= fee { total_value - fee } else { 0 };
            }

            let amount = match amount == "ALL" {
                true => ntotal,
                false => core::amount_from_hr_string(amount).map_err(|_| ErrorKind::InvalidAmount(amount.to_string()))?,
            };

            // Preparign for sync update progress printing
            let running = Arc::new( AtomicBool::new(true) );
            let (tx, rx) = mpsc::channel();
            // Starting printing to console thread.
            let updater = grin_wallet_libwallet::api_impl::owner_updater::start_updater_console_thread(rx, running.clone())?;
            let status_send_channel = Some(tx);

            // Store slate in a file
            if let Some(input) = input {
                let mut file = File::create(input.replace("~", &home_dir))?;
                let w = wallet.lock();
                let address = Some(String::from("file"));
                let slate = w.initiate_send_tx(
                    address.clone(),
                    amount,
                    confirmations,
                    strategy,
                    change_outputs,
                    500,
                    message,
                    output_list,
                    version,
                    routputs,
                    &status_send_channel,
                    ttl_blocks,
                )?;

                file.write_all(serde_json::to_string(&slate)?.as_bytes())?;

                w.tx_lock_outputs(
                    &slate,
                    address,
                    0)?;

                cli_message!("{} created successfully.", input);

                // Stopping updater, sync should be done by now
                running.store(false, Ordering::Relaxed);
                let _ = updater.join();

                return Ok(());
            }

            let mut to = to.unwrap().to_string();
            let mut display_to = None;

            if to.starts_with("@") {
                let contact = address_book.lock().get_contact(&to[1..])?;
                to = contact.get_address().to_string();
                display_to = Some(contact.get_name().to_string());
            }
            // try parse as a general address and fallback to mwcmqs address
            let address = Address::parse(&to);
            let address: Result<Box<dyn Address>, Error> = match address {
                Ok(address) => Ok(address),
                Err(e) => {
                    Ok(Box::new(MWCMQSAddress::from_str(&to).map_err(|_| e)?) as Box<dyn Address>)
                }
            };

            let to = address?;
            if display_to.is_none() {	
                display_to = Some(to.get_stripped());	
            }

            let w = wallet.lock();
            let address = Some(to.to_string());
            let mut slate = w.initiate_send_tx(
                address.clone(),
                amount,
                confirmations,
                strategy,
                change_outputs,
                500,
                message,
                output_list,
                version,
                1,
                &status_send_channel,
                ttl_blocks,
            )?;

            // Stopping updater, sync should be done by now
            running.store(false, Ordering::Relaxed);
            let _ = updater.join();

            let method = match to.address_type() {
                AddressType::MWCMQS => "mwcmqs",
                AddressType::Keybase => "keybase",
                AddressType::Https => "http",
            };

            let original_slate = slate.clone();

            let mut tor_config = grin_wallet_config::TorConfig::default();
            tor_config.send_config_dir = absolute_path(config.get_top_level_directory()?)?.into_os_string().into_string().unwrap();
            let sender = grin_wallet_impls::create_sender(method, &to.to_string(), &apisecret, Some(tor_config))?;
            slate = sender.send_tx(&slate)?;

            // Sender can chenge that, restoring original value
            slate.ttl_cutoff_height = original_slate.ttl_cutoff_height.clone();
            // Checking is sender didn't do any harm to slate
            Slate::compare_slates_send( &original_slate, &slate)?;

            w.tx_lock_outputs(&slate, address,0)?;
            w.finalize_post_slate( &mut slate, fluff)?;

            let ret_id = w.get_id(slate.id)?;
            cli_message!(	
                    "Transaction [{}] for [{}] MWCs sent successfully to [{}]",	
                slate.id.to_string(),	
                core::amount_to_hr_string(slate.amount, false),	
                display_to.unwrap()	
            );
            println!("txid={:?}", ret_id);
        }
        Some("invoice") => {
            let args = matches.subcommand_matches("invoice").unwrap();
            let to = args.value_of("to").unwrap();
            let outputs = args.value_of("outputs").unwrap_or("1");
            let outputs = usize::from_str_radix(outputs, 10)
                .map_err(|_| ErrorKind::InvalidNumOutputs(outputs.to_string()))?;
            let amount = args.value_of("amount").unwrap();
            let amount = core::amount_from_hr_string(amount)
                .map_err(|_| ErrorKind::InvalidAmount(amount.to_string()))?;
            let fluff = args.is_present("fluff");

            let mut to = to.to_string();
            let mut display_to = None;
            if to.starts_with("@") {
                let contact = address_book.lock().get_contact(&to[1..])?;
                to = contact.get_address().to_string();
                display_to = Some(contact.get_name().to_string());
            }

            // try parse as a general address
            let address = Address::parse(&to);
            let address: Result<Box<dyn Address>, Error> = match address {
                Ok(address) => Ok(address),
                Err(e) => {
                    Ok(Box::new(MWCMQSAddress::from_str(&to).map_err(|_| e)?) as Box<dyn Address>)
                }
            };

            let to = address?;
            if display_to.is_none() {
                display_to = Some(to.get_stripped());
            }

            let mut slate = wallet.lock().initiate_receive_tx(Some(to.to_string()) ,amount, outputs)?;

            let method = match to.address_type() {
                AddressType::MWCMQS => "mwcmqs",
                AddressType::Keybase => "keybase",
                AddressType::Https => return Err(ErrorKind::HttpRequest(format!("Invoice doesn't support address type: {:?}", to.address_type())).into()),
            };

            // Invoices supported by MQS and Keybase only. HTTP based transport works differently, no invoice processing on them.
            let original_slate = slate.clone();
            let sender = grin_wallet_impls::create_sender(method, &to.to_string(), &None, None)?;
            slate = sender.send_tx(&slate)?;
            // Sender can chenge that, restoring original value
            slate.ttl_cutoff_height = original_slate.ttl_cutoff_height.clone();
            // Checking is sender didn't do any harm to slate
            Slate::compare_slates_invoice( &original_slate, &slate)?;

            { // Do exactly what send does..
                let w = wallet.lock();
                w.tx_lock_outputs(&slate, Some(to.to_string()), 0)?;
                w.finalize_post_slate(&mut slate, fluff)?;
            }

            // Locking for this slate is skipped. Transaction will be received at return state
            cli_message!(
                "invoice slate [{}] for [{}] MWCs sent successfully to [{}]",
                slate.id.to_string(),
                core::amount_to_hr_string(slate.amount, false),
                display_to.unwrap()
            );
        }
        Some("restore") => {
            *out_is_safe = false;
            if keybase_broker.is_some() {
                return Err(ErrorKind::HasListener.into());
            }
            let args = matches.subcommand_matches("restore").unwrap();
            let passphrase = match args.is_present("passphrase") {
                true => password_prompt(args.value_of("passphrase")),
                false => "".to_string(),
            };
            *out_is_safe = args.value_of("passphrase").is_none();

            println!("restoring... please wait as this could take a few minutes to complete.");

            let passphrase = ZeroingString::from(passphrase.as_str());

            {
                let mut w = wallet.lock();
                let seed = w.init(config, passphrase.clone(), false)?;
                w.complete(seed, config, "default", passphrase.clone(), true)?;
                w.restore_state()?;
                w.update_tip_as_last_scanned()?;
            }

            derive_address_key(config, wallet)?;
            if passphrase.is_empty() {
                println!("{}: wallet with no passphrase.", "WARNING".bright_yellow());
            }

            println!("wallet restoration done!");
            return Ok(());
        }
        Some("recover") => {
            *out_is_safe = false;
            if keybase_broker.is_some()  {
                return Err(ErrorKind::HasListener.into());
            }
            let args = matches.subcommand_matches("recover").unwrap();
            let passphrase = match args.is_present("passphrase") {
                true => password_prompt(args.value_of("passphrase")),
                false => "".to_string(),
            };
            *out_is_safe = args.value_of("passphrase").is_none();

            let passphrase = ZeroingString::from(passphrase.as_str());

            if let Some(words) = args.values_of("words") {
                println!("recovering... please wait as this could take a few minutes to complete.");

                if  getenv("MWC_MNEMONIC")?.is_some() {
                    let envvar = env::var("MWC_MNEMONIC")?;
                    let words: Vec<&str> = envvar.split(" ").collect();
                    {
                        println!("Recovering with environment variable words: {:?}", words);
                        let mut w = wallet.lock();
                        w.restore_seed( config, &words, passphrase.clone())?;
                        let seed = w.init(config, passphrase.clone(), false)?;
                        w.complete(seed, config, "default", passphrase.clone(), true)?;
                        w.restore_state()?;
                    }
                }
                else
                {
                    let words: Vec<&str> = words.collect();
                    {
                        println!("Recovering with commandline specified words: {:?}", words);
                        let mut w = wallet.lock();
                        w.restore_seed(config, &words, passphrase.clone())?;
                        let seed = w.init(config, passphrase.clone(), false)?;
                        w.complete(seed, config, "default", passphrase.clone(), true)?;
                        w.restore_state()?;
                    }
                }

                derive_address_key(config, wallet)?;
                if passphrase.is_empty() {
                    println!("{}: wallet with no passphrase.", "WARNING".bright_yellow());
                }

                println!("wallet restoration done!");
                *out_is_safe = false;
                return Ok(());
            } else if args.is_present("display") {
                let w = wallet.lock();
                w.show_mnemonic(config, passphrase)?;
                return Ok(());
            }
        }
        Some("check") => {
            let args = matches.subcommand_matches("check").unwrap();

            let start_height = args.value_of("start_height").unwrap_or("1");
            let start_height = u64::from_str_radix(start_height, 10)
                .map_err(|_| ErrorKind::InvalidNumOutputs(start_height.to_string()))?;

            if keybase_broker.is_some() || mwcmqs_broker.is_some() {
                return Err(ErrorKind::HasListener.into());
            }
            println!("checking and repairing... please wait as this could take a few minutes to complete.");
            let wallet = wallet.lock();
            wallet.check_repair( start_height, !args.is_present("--no-delete_unconfirmed"))?;
            cli_message!("check and repair done!");
        }
        Some("sync") => {
            match wallet.lock().sync() {
                Ok(synced) => if synced {
                    cli_message!("Your wallet data successfully synchronized with a node");
                }
                else {
                    cli_message!("Warning: Unable to sync wallet with a node");
                },
                Err(e) => cli_message!("Warning: Unable to sync wallet with a node, {}", e),
            }
        }
        Some("dump-wallet-data") => {
            let args = matches.subcommand_matches("dump-wallet-data").unwrap();
            let file_name = args.value_of("file").map(|input| input.replace("~", &home_dir));
            wallet.lock().dump_wallet_data(file_name)?;
        }
        Some("set-recv") => {
            let args = matches.subcommand_matches("set-recv").unwrap();
            let account = args.value_of("account").unwrap();
            if wallet.lock().account_path(account)?.is_some() {
                grin_wallet_libwallet::set_receive_account(account.to_string());
                cli_message!("Incoming funds will be received in account: {}", account);
            }
            else
            {
                cli_message!("Account {} does not exist!", account);
            }
        }
        Some("getrootpublickey") => {
            let args = matches.subcommand_matches("getrootpublickey").unwrap();
            let message = args.value_of("message");
            let mut w = wallet.lock();
            w.getrootpublickey(message)?;
        }
        Some("verifysignature") => {
            let args = matches.subcommand_matches("verifysignature").unwrap();
            let message = args.value_of("message").unwrap();
            let signature = args.value_of("signature").unwrap();
            let pubkey = args.value_of("pubkey").unwrap();

            // Note. We don't need any wallet access, we just need tools and API that wallet has.
            // Also want to keep wallet API pattern
            let mut w = wallet.lock();
            w.verifysignature(message, signature, pubkey)?;
        }
        Some("scan_outputs") => {
            let args = matches.subcommand_matches("scan_outputs").unwrap();

            let pub_key_file = args.value_of("pubkey_file").unwrap();

            let file = File::open(pub_key_file)
                .map_err(|e| ErrorKind::FileNotFound( pub_key_file.to_string(), format!("{}",e)) )?;

            let output_fn = format!("{}.commits", pub_key_file);

            if std::fs::metadata(output_fn.clone()).is_ok() {
                std::fs::remove_file(output_fn.clone()).map_err( |_| ErrorKind::FileUnableToDelete(output_fn.clone()) )?;
            }


            let mut pub_keys = Vec::new();

            for line in io::BufReader::new(file).lines() {
                let pubkey_str = line.map_err(|e| ErrorKind::FileNotFound( pub_key_file.to_string(), format!("{}",e)) )?;
                if pubkey_str.is_empty() {
                    continue;
                }

                match  PublicKey::from_hex(&pubkey_str ) {
                    Ok(pk) => { pub_keys.push(pk); }
                    _ => { cli_message!(
                                "{}: unable to read a public key `{}`. Will be skipped.",
                                "WARNING".bright_yellow(), pubkey_str );
                    }
                }
            }

            println!("Scaning outputs for {} public keys. Please wait as this could take a few minutes to complete.", pub_keys.len() );
            let mut wallet = wallet.lock();
            wallet.scan_outputs( pub_keys, output_fn.clone() )?;
            cli_message!("scanning of the outputs is completed! result file location: {}", output_fn );
        }
        Some("export-proof") => {
            let args = matches.subcommand_matches("export-proof").unwrap();
            let input = args.value_of("file").unwrap();
            let id = args.value_of("id").unwrap();
            let id = id
                .parse::<u32>()
                .map_err(|_| ErrorKind::InvalidTxId(id.to_string()))?;
            let w = wallet.lock();
            let tx_proof = w.get_tx_proof(id)?;
            match w.verify_tx_proof(&tx_proof) {
                Ok((sender, receiver, amount, outputs, kernel)) => {
                    let mut file = File::create(input.replace("~", &home_dir))?;
                    file.write_all(serde_json::to_string(&tx_proof)?.as_bytes())?;
                    println!("proof written to {}", input);
                    proof_ok(sender, receiver, amount, outputs, kernel);
                }
                Err(e) => {
                    cli_message!("unable to verify proof, {}", e);
                }
            }
        }
        Some("verify-proof") => {
            let args = matches.subcommand_matches("verify-proof").unwrap();
            let input = args.value_of("file").unwrap();
            let path = Path::new(&input.replace("~", &home_dir)).to_path_buf();
            if !path.exists() {
                return Err(ErrorKind::FileNotFound(input.to_string(), "path doesn't exist".to_string()).into());
            }
            let mut file = File::open(path)?;
            let mut proof = String::new();
            file.read_to_string(&mut proof)?;
            let tx_proof: TxProof = serde_json::from_str(&proof)?;

            let wallet = wallet.lock();
            match wallet.verify_tx_proof(&tx_proof) {
                Ok((sender, receiver, amount, outputs, kernel)) => {
                    proof_ok(sender, receiver, amount, outputs, kernel);
                }
                Err(e) => {
                    cli_message!("unable to verify proof, {}", e);
                }
            }
        }
        Some(subcommand) => {
            cli_message!(
                "{}: subcommand `{}` not implemented!",
                "ERROR".bright_red(),
                subcommand.bright_green()
            );
        }
        None => {}
    };

    Ok(())
}

#[cfg(windows)]
pub fn enable_ansi_support() {
    if !ansi_term::enable_ansi_support().is_ok() {
        colored::control::set_override(false);
    }
}

#[cfg(not(windows))]
pub fn enable_ansi_support() {
}
