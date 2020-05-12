use failure::Fail;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Transaction model not found!")]
    TransactionModelNotFound,
    #[fail(display = "could not open wallet seed!")]
    WalletSeedCouldNotBeOpened,
    #[fail(display = "transaction doesn't have a proof!")]
    TransactionHasNoProof,
    #[fail(
        display = "invalid transaction id given: `{}`",
        0
    )]
    InvalidTxId(String),
    #[fail(display = "invalid amount given: `{}`", 0)]
    InvalidAmount(String),
    #[fail(
        display = "--outputs must be specified when selection strategy is 'custom'"
    )]
    CustomWithNoOutputs,
    #[fail(
        display = "--outputs must not be specified unless selection strategy is 'custom'"
    )]
    NonCustomWithOutputs,
    #[fail(
        display = "invalid selection strategy, use either 'smallest', 'all', or 'custom'"
    )]
    InvalidStrategy,
    #[fail(
        display = "invalid number of minimum confirmations given: `{}`",
        0
    )]
    InvalidMinConfirmations(String),
    #[fail(
        display = "invalid pagination length: `{}`",
        0
    )]
    InvalidPaginationLength(String),
    #[fail(
    display = "invalid transaction id number: `{}`",
    0
    )]
    InvalidTxIdNumber(String),
    #[fail(
    display = "invalid transaction UUID: `{}`",
    0
    )]
    InvalidTxUuid(String),
    #[fail(
        display = "invalid pagination start: `{}`", 
        0
    )]
    InvalidPaginationStart(String),
    #[fail(
        display = "invalid number of outputs given: `{}`",
        0
    )]
    InvalidNumOutputs(String),
    #[fail(
        display = "invalid slate version given: `{}`",
        0
    )]
    InvalidSlateVersion(String),
    #[fail(
        display = "could not unlock wallet! are you using the correct passphrase?"
    )]
    WalletUnlockFailed,
    #[fail(
        display = "Zero-conf Transactions are not allowed. Must have at least 1 confirmation."
    )]
    ZeroConfNotAllowed,

    #[fail(display = "The wallet is locked. Please use `unlock` first.")]
    WalletIsLocked,

    #[fail(display = "could not open wallet! use `unlock` or `init`.")]
    NoWallet,
    #[fail(
        display = "{} listener is closed! consider using `listen` first.",
        0
    )]
    ClosedListener(String),

    #[fail(
        display = "listener for {} already started!",
        0
    )]
    AlreadyListening(String),
    #[fail(
        display = "contact named `{}` already exists!",
        0
    )]
    ContactAlreadyExists(String),
    #[fail(
        display = "could not find contact named `{}`!",
        0
    )]
    ContactNotFound(String),

    #[fail(display = "could not parse number from string!")]
    NumberParsingError,

    #[fail(display = "could not send keybase message!, {}", _0)]
    KeybaseMessageSendError(String),
    #[fail(display = "failed receiving slate!, {}", _0)]
    GrinWalletReceiveError(String),
    #[fail(display = "failed verifying slate messages!, {}", _0)]
    GrinWalletVerifySlateMessagesError(String),
    #[fail(display = "failed finalizing slate!, {}", _0)]
    GrinWalletFinalizeError(String),
    #[fail(display = "failed posting transaction!, {}", _0)]
    GrinWalletPostError(String),
    #[fail(
        display = "keybase not found! consider installing keybase locally first."
    )]
    KeybaseNotFound,
    #[fail(
        display = "rejecting invoice as auto invoice acceptance is turned off!"
    )]
    DoesNotAcceptInvoices,
    #[fail(
        display = "rejecting invoice as amount '{}' is too big!",
        0
    )]
    InvoiceAmountTooBig(u64),
    #[fail(
        display = "please stop the listeners before doing this operation"
    )]
    HasListener,
    #[fail(display = "wallet already unlocked")]
    WalletAlreadyUnlocked,
    #[fail(display = "Error getting tx proof stored")]
    TxStoredProof,

    #[fail(display = "http request error, {}", _0)]
    HttpRequest(String),
    #[fail(display = "Generic error, {}", 0)]
    GenericError(String),
    #[fail(display = "unable to verify proof, {}", _0)]
    VerifyProof(String),
    #[fail(display = "file '{}' not found, {}", _0, _1)]
    FileNotFound(String, String),
    #[fail(display = "unable to delete the file '{}'", 0)]
    FileUnableToDelete(String),
    #[fail(display = "unable to create the file '{}', {}", _0, _1)]
    FileUnableToCreate(String, String),

    #[fail(display = "unable to get public key, {}", _0)]
    GetPublicKeyError(String),

    #[fail(display = "Account {} does not exist", _0)]
    AccountNotExist(String),
}
