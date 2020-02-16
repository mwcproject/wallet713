use failure::Fail;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "secp error")]
    Secp,
    #[fail(display = "model not found!")]
    ModelNotFound,
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

    #[fail(display = "could not open wallet! use `unlock` or `init`.")]
    NoWallet,
    #[fail(
        display = "{} listener is closed! consider using `listen` first.",
        0
    )]
    ClosedListener(String),
    #[fail(
        display = "{} Sender returned invalid response.",
        0
    )]
    InvalidRespose(String),
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
    #[fail(display = "invalid character!")]
    InvalidBase58Character(char, usize),
    #[fail(display = "invalid length!")]
    InvalidBase58Length,
    #[fail(display = "invalid checksum!")]
    InvalidBase58Checksum,
    #[fail(display = "invalid network!")]
    InvalidBase58Version,
    #[fail(display = "invalid key!")]
    InvalidBase58Key,
    #[fail(display = "could not parse number from string!")]
    NumberParsingError,
    #[fail(display = "unknown address type `{}`!", 0)]
    UnknownAddressType(String),
    #[fail(
        display = "could not parse `{}` to a mwcmq address!",
        0
    )]
    GrinboxAddressParsingError(String),
    #[fail(
        display = "could not parse `{}` to a keybase address!",
        0
    )]
    KeybaseAddressParsingError(String),
    #[fail(
        display = "could not parse `{}` to a https address!",
        0
    )]
    HttpsAddressParsingError(String),
    #[fail(display = "could not send keybase message!")]
    KeybaseMessageSendError,
    #[fail(display = "failed receiving slate!")]
    GrinWalletReceiveError,
    #[fail(display = "failed verifying slate messages!")]
    GrinWalletVerifySlateMessagesError,
    #[fail(display = "failed finalizing slate!")]
    GrinWalletFinalizeError,
    #[fail(display = "failed posting transaction!")]
    GrinWalletPostError,
    #[fail(
        display = "keybase not found! consider installing keybase locally first."
    )]
    KeybaseNotFound,
    #[fail(display = "mwcmq websocket terminated unexpectedly!")]
    GrinboxWebsocketAbnormalTermination,
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
    #[fail(display = "unable to encrypt message")]
    Encryption,
    #[fail(display = "unable to decrypt message")]
    Decryption,
    #[fail(display = "http request error")]
    HttpRequest,
    #[fail(display = "{}", 0)]
    GenericError(String),
    #[fail(display = "unable to verify proof")]
    VerifyProof,
    #[fail(display = "file '{}' not found", 0)]
    FileNotFound(String),
    #[fail(display = "unable to delete the file '{}'", 0)]
    FileUnableToDelete(String),
    #[fail(display = "unable to create the file '{}'", 0)]
    FileUnableToCreate(String),

    #[fail(display = "Tx Proof unable to parse address '{}'", 0)]
    TxProofParseAddress(String),
    #[fail(display = "Tx Proof unable to parse an address as a public key")]
    TxProofParsePublicKey,

    #[fail(display = "Tx Proof unable to parse signature '{}'", 0)]
    TxProofParseSignature(String),

    #[fail(display = "Tx Proof unable to verify signature")]
    TxProofVerifySignature,
    #[fail(display = "Tx Proof unable to parse ecrypted message")]
    TxProofParseEncryptedMessage,
    #[fail(display = "Tx Proof unable to verify destination address")]
    TxProofVerifyDestination,

    #[fail(display = "Tx Proof unable to build a key")]
    TxProofDecryptionKey,
    #[fail(display = "Tx Proof unable to decrypt the message")]
    TxProofDecryptMessage,
    #[fail(display = "Tx Proof unable to build a slate from the message")]
    TxProofParseSlate,
}
