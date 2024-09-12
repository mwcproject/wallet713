use std::env::VarError;

#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
    #[error("could not open wallet seed!")]
    WalletSeedCouldNotBeOpened,
    #[error("transaction doesn't have a proof!")]
    TransactionHasNoProof,
    #[error("invalid transaction id given: `{0}`")]
    InvalidTxId(String),
    #[error("invalid amount given: `{0}`")]
    InvalidAmount(String),
    #[error("--outputs must be specified when selection strategy is 'custom'")]
    CustomWithNoOutputs,
    #[error("proof address of receiver address should match {0},{1}")]
    ProofAddresMismatch(String, String),
    #[error("--outputs must not be specified unless selection strategy is 'custom'")]
    NonCustomWithOutputs,
    #[error("invalid selection strategy, use either 'smallest', 'all', or 'custom'")]
    InvalidStrategy,
    #[error("invalid number of ttl_blocks given: `{0}`")]
    InvalidTTLBlocks(String),
    #[error("invalid number of minimum confirmations given: `{0}`")]
    InvalidMinConfirmations(String),
    #[error("invalid pagination length: `{0}`")]
    InvalidPaginationLength(String),
    #[error("Tor Error: `{0}`")]
    InvalidTxIdNumber(String),
    #[error("invalid transaction UUID: `{0}`")]
    InvalidTxUuid(String),
    #[error("invalid pagination start: `{0}`")]
    InvalidPaginationStart(String),
    #[error("invalid number of outputs given: `{0}`")]
    InvalidNumOutputs(String),
    #[error("invalid slate version given: `{0}`")]
    InvalidSlateVersion(String),
    #[error("could not unlock wallet! are you using the correct passphrase?")]
    WalletUnlockFailed,
    #[error("Zero-conf Transactions are not allowed. Must have at least 1 confirmation.")]
    ZeroConfNotAllowed,
    #[error("The wallet is locked. Please use `unlock` first.")]
    WalletIsLocked,
    #[error("could not open wallet! use `unlock` or `init`.")]
    NoWallet,
    #[error("{0} listener is closed! consider using `listen` first.")]
    ClosedListener(String),
    #[error("{0} To address was not specified.")]
    ToNotSpecified(String),
    #[error("listener for {0} already started!")]
    AlreadyListening(String),
    #[error("contact named `{0}` already exists!")]
    ContactAlreadyExists(String),
    #[error("could not find contact named `{0}`!")]
    _ContactNotFound(String),
    #[error("could not parse number from {0}")]
    NumberParsingError(String),
    #[error("failed receiving slate!, {0}")]
    GrinWalletReceiveError(String),
    #[error("failed verifying slate messages!, {0}")]
    GrinWalletVerifySlateMessagesError(String),
    #[error("failed finalizing slate!, {0}")]
    GrinWalletFinalizeError(String),
    #[error("failed posting transaction!, {0}")]
    GrinWalletPostError(String),
    #[error("please stop the listeners before doing this operation")]
    HasListener,
    #[error("wallet already unlocked")]
    WalletAlreadyUnlocked,
    #[error("Error: Payment proof not found - please update receiver wallet to a newer version and ensure the --proof option is specified on send commands")]
    TxStoredProof,
    #[error("http request error, {0}")]
    HttpRequest(String),
    #[error("Generic error, {0}")]
    GenericError(String),
    #[error("file '{0}' not found, {1}")]
    FileNotFound(String, String),
    #[error("unable to delete the file '{0}'")]
    FileUnableToDelete(String),
    #[error("unable to create the file '{0}', {1}")]
    FileUnableToCreate(String, String),
    #[error("Invalid argument: {0}")]
    ArgumentError(String),
    #[error("Wallet error: {0}")]
    LibWalletError(#[from] grin_wallet_libwallet::Error),
    #[error("Secp error: {0}")]
    SecpError(#[from] grin_util::secp::Error),
    #[error("Keychain error: {0}")]
    KeychainError(#[from] grin_keychain::Error),
    #[error("IO error: {0}")]
    IOError(String),
    #[error("Swap error: {0}")]
    SwapError(#[from] grin_wallet_libwallet::swap::Error),
    #[error("Wallet error: {0}")]
    WalletError(#[from] grin_wallet_impls::Error),
    #[error("Controller error: {0}")]
    ControllerError(#[from] grin_wallet_controller::Error),
    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Parse error: {0}")]
    CoreParseError(#[from] grin_core::ser::Error),
    #[error("Json error: {0}")]
    JsonError(String),
    #[error("Var error: {0}")]
    VarError(#[from] VarError),
    #[error("Toml error: {0}")]
    TomlError(#[from] toml::de::Error),
    #[error("Toml error: {0}")]
    TomlSerError(#[from] toml::ser::Error),
    #[error("Tokenizer error: {0}")]
    TokenizerError(String),
    #[error("Parsing error: {0}")]
    ClapError(String),
    #[error("Storage error: {0}")]
    StoreError(#[from] grin_store::Error),

}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IOError(format!("{}", e))
    }
}
