# mwc713 API Documentation

### Overview

mwc713 supports both an 'Owner API' and a 'Foreign API'. The owner api controls functions that the owner of the wallet may only access and the foreign API is for receiving payments and invoices and may be accessed by the public.

### Authentication

API is using base Authentication with user 'mwc' and password from the config XXXXX_api_secret.

### TLS/SSL connection for API.

In order to activate the secure connection you have to specify certificates stored at pem files

| parameter | value |
| --------- | ------ |
| tls_certificate_file | path of TLS certificate file, self-signed certificates are not supported  |
| tls_certificate_key  | private key for the TLS certificate |
 
### Owner API Documentation

The owner API must be configured on startup. The parameters which go into your mwc713.toml configuration file are as follows:

| parameter | value |
| --------- | ------ |
| owner_api | true |
| owner_api_address | The ip address:port to bind to for example: 127.0.0.1:13415. |
| owner_api_secret | The Basic Auth secret to connect to the owner API. |

A sample, configuration may look like this:

```
chain = "Floonet"
wallet713_data_path = "wallet713_data"
keybase_listener_auto_start = true
default_keybase_ttl = "24h"
owner_api = true
owner_api_address = "127.0.0.1:13415"
owner_api_secret = "password"
```
Optionally, if you would like to send via keybase, you must configure the keybase listener to auto start using the keybase_listener_auto_start parameter (see above).

Below is the documentation for the individual API end points:

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/node_height</td><td>Node height returns the number of blocks that is seen by the full node that this mwc713 instance is connected to.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/wallet/owner/node_height</code></td></tr>
  <tr><td colspan=2><code>{"height": 173393}</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/retrieve_summary_info</td><td>Summary info returns the same data that is returned when you run the info command from the command line interface of mwc713. This includes the height, total balance, balance awaiting confirmations, amount that is immature (mined mwc that is less than 1440 blocks old), spendable balance, and locked balance.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/wallet/owner/retrieve_summary_info</code></td></tr>
  <tr><td colspan=2><code>{"last_confirmed_height":145169,"minimum_confirmations":10,"total":30575500000,"amount_awaiting_confirmation":0,"amount_immature":0,"amount_currently_spendable":30575500000,"amount_locked":0}</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/retrieve_outputs</td><td>This api retrieves the informations about the unspent outputs that are owned by this mwc713 instance. The response includes the root_key_id, key_id, n_child, commit, mmr_index (if applicable), value, status, height, lock_height, is_coinbase, and tx_log_entry for each unspent output in the wallet. It is returned in a json array.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/wallet/owner/retrieve_outputs</code></td></tr>
  <tr><td colspan=2><code>
[false,[[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001ad00000000","n_child":429,"commit":"0939ea60b67648c4e505a4e5a6c579d1ea6f16d3245083b182e1d3893f845826da","mmr_index":null,"value":30575500000,"status":"Unspent","height":145016,"lock_height":0,"is_coinbase":false,"tx_log_entry":164},[9,57,234,96,182,118,72,196,229,5,164,229,166,197,121,209,234,111,22,211,36,80,131,177,130,225,211,137,63,132,88,38,218]],[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001b700000000","n_child":439,"commit":"093206e1f7b72205e8264ca2da1ae5459c1dfd0c0e9572ec7949e0d34d0974eea9","mmr_index":null,"value":5000000000,"status":"Unconfirmed","height":145187,"lock_height":0,"is_coinbase":false,"tx_log_entry":165},[9,50,6,225,247,183,34,5,232,38,76,162,218,26,229,69,156,29,253,12,14,149,114,236,121,73,224,211,77,9,116,238,169]],[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001b800000000","n_child":440,"commit":"0956eea613dafd1ed36626291a4bea327ef2175c78e9fe1826bac78e615a7c66fb","mmr_index":null,"value":5000000000,"status":"Unconfirmed","height":145187,"lock_height":0,"is_coinbase":false,"tx_log_entry":166},[9,86,238,166,19,218,253,30,211,102,38,41,26,75,234,50,126,242,23,92,120,233,254,24,38,186,199,142,97,90,124,102,251]],[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001b900000000","n_child":441,"commit":"095899be912e0dc3d1635a6ff0adb79db1cbe2db75a01b175a39c64d45587716fd","mmr_index":null,"value":5000000000,"status":"Unconfirmed","height":145187,"lock_height":0,"is_coinbase":false,"tx_log_entry":167},[9,88,153,190,145,46,13,195,209,99,90,111,240,173,183,157,177,203,226,219,117,160,27,23,90,57,198,77,69,88,119,22,253]]]]</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/retrieve_txs</td><td>This api retrieves the informations about the transactions that have taken place in this mwc713 instance. The fields shown are parent_key_id, id, tx_slate_id, tx_type (TxSent/TxReceived/(Canceled)), address, createion_ts (timestamp), confirmation_ts, confirmed, num_inputs, num_outputs, amount_credited (in nanomwc), amount_debited (in nanomwc), and the fee (for sends).</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/wallet/owner/retrieve_txs</code></td></tr>
  <tr><td colspan=2><code>
[false,[{"parent_key_id":"0200000000000000000000000000000000","id":0,"tx_slate_id":"56bb520d-0449-4876-8274-5a9b2ec408d8","tx_type":"TxSent","address":null,"creation_ts":"2019-09-04T15:56:44.938712Z","confirmation_ts":"2019-09-05T05:21:24.868739Z","confirmed":true,"num_inputs":0,"num_outputs":1,"amount_credited":5000000000,"amount_debited":0,"fee":null},{"parent_key_id":"0200000000000000000000000000000000","id":1,"tx_slate_id":"78ccba26-c078-4a65-9364-59a6d4d86a4b","tx_type":"TxSent","address":null,"creation_ts":"2019-09-04T15:56:47.340871Z","confirmation_ts":"2019-09-05T05:21:24.868862Z","confirmed":true,"num_inputs":0,"num_outputs":1,"amount_credited":5000000000,"amount_debited":0,"fee":null},{"parent_key_id":"0200000000000000000000000000000000","id":2,"tx_slate_id":"3dccce97-241f-4646-a62a-6e6b2f002204","tx_type":"TxSent","address":"mwcmqs://xmiyrN5erhG4MvuGgn9on8R7B8PUeQJEWsYjeZcKXJ52aofjhHUA","creation_ts":"2019-09-05T05:21:45.087966Z","confirmation_ts":"2019-09-05T05:23:16.677434Z","confirmed":true,"num_inputs":1,"num_outputs":1,"amount_credited":3992000000,"amount_debited":5000000000,"fee":8000000},{"parent_key_id":"0200000000000000000000000000000000","id":3,"tx_slate_id":"ff5ffdea-2f0a-41a0-b7b0-ca8d072e8759","tx_type":"TxReceived","address":"mwcmqs://xmiyrN5erhG4MvuGgn9on8R7B8PUeQJEWsYjeZcKXJ52aofjhHUA","creation_ts":"2019-09-05T05:23:42.103007Z","confirmation_ts":"2019-09-05T14:12:07.105350Z","confirmed":true,"num_inputs":0,"num_outputs":1,"amount_credited":1000000000,"amount_debited":0,"fee":null},{"parent_key_id":"0200000000000000000000000000000000","id":4,"tx_slate_id":"bc5f243c-1793-4998-9ede-a4ab52cd4823","tx_type":"TxReceived","address":"mwcmqs://xmgehLCvsHXdoAenuUARvQGMPkzJdm5Qb1wTQVi2WnRaSjC1CWgH","creation_ts":"2019-09-05T14:14:15.952203Z","confirmation_ts":"2019-09-05T14:15:55.182521Z","confirmed":true,"num_inputs":0,"num_outputs":1,"amount_credited":1000000000,"amount_debited":0,"fee":null},{"parent_key_id":"0200000000000000000000000000000000","id":5,"tx_slate_id":"a968957c-8cb4-4c88-b061-6e17ee53e970","tx_type":"TxReceived","address":"mwcmqs://xmgehLCvsHXdoAenuUARvQGMPkzJdm5Qb1wTQVi2WnRaSjC1CWgH","creation_ts":"2019-09-05T14:17:38.143642Z","confirmation_ts":"2019-09-05T14:31:09.585312Z","confirmed":true,"num_inputs":0,"num_outputs":1,"amount_credited":1000000000,"amount_debited":0,"fee":null},{"parent_key_id":"0200000000000000000000000000000000","id":6,"tx_slate_id":"04e8bdc7-6d27-4f91-b4de-ad4b5ed153c4","tx_type":"TxReceived","address":"mwcmqs://xmgehLCvsHXdoAenuUARvQGMPkzJdm5Qb1wTQVi2WnRaSjC1CWgH","creation_ts":"2019-09-05T14:31:35.079979Z","confirmation_ts":"2019-09-05T14:57:07.809607Z","confirmed":true,"num_inputs":0,"num_outputs":1,"amount_credited":1000000000,"amount_debited":0,"fee":null},{"parent_key_id":"0200000000000000000000000000000000","id":7,"tx_slate_id":"5f59cb89-27a2-4b0d-97e4-dbfb19b39efc","tx_type":"TxSent","address":"mwcmqs://xmgehLCvsHXdoAenuUARvQGMPkzJdm5Qb1wTQVi2WnRaSjC1CWgH","creation_ts":"2019-09-05T14:57:27.911072Z","confirmation_ts":"2019-09-05T15:23:07.612600Z","confirmed":true,"num_inputs":2,"num_outputs":1,"amount_credited":993000000,"amount_debited":2000000000,"fee":7000000}]]</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/cancel_tx</td><td>This api cancels a transaction. The id of the transaction to cancel is specified as part of the query string using the parameter 'id'. See curl example below.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/wallet/owner/cancel_tx?id=17</code></td></tr>
  <tr><td colspan=2><code>
{"success": true}
    or
{"error": "TransactionNotCancellable"}
    or
{"error": "TransactionDoesntExist"}
</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/issue_send_tx</td><td>The issue send tx API sends payments via your mwc713 wallet instance. As shown in the curl example, you can specify the following values: method (mwcmqs and keybase are the supported methods for sending at the moment), amount (amount in nanomwc 1 billion nanomwc = 1 mwc.), minimum confirmations (only select from outputs that have at least this many confirmations), max_outputs (the maximum number of outputs to use in this transaction), num_change_outputs (the number of change outputs to specify in this transaction), selection_strategy_is_use_all (whether or not to use all outputs in this transaction), dest (the destination for mwcmqs, it is an mwcmqs address of the recipient, for keybase it is the user's keybase id). The response, if successful, will be the slate that was sent.</td></tr>
  <tr><td colspan=2><code># curl -u mwc -X POST http://127.0.0.1:13415//v1/wallet/owner/issue_send_tx -d '{"method": "mwcmqs", "amount": 100000000, "minimum_confirmations": 1, "max_outputs": 10, "num_change_outputs": 1, "selection_strategy_is_use_all": true, "dest": "xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU"}' http://localhost:13415/v1/wallet/owner/issue_send_tx</code></td></tr>
  <tr><td colspan=2><code>{"version_info":{"version":2,"orig_version":2,"block_header_version":1},"num_participants":2,"id":"0be1b04a-7172-4c94-a3f1-ea8071563d5f","tx":{"offset":"d899eff1345a07fb67b0d43dc83f9e64e1d11b75c2e4760b9c2058372f9895b9","body":{"inputs":[{"features":"Plain","commit":"093206e1f7b72205e8264ca2da1ae5459c1dfd0c0e9572ec7949e0d34d0974eea9"},{"features":"Plain","commit":"095899be912e0dc3d1635a6ff0adb79db1cbe2db75a01b175a39c64d45587716fd"},{"features":"Plain","commit":"08970fe5bbbcc456446f56b310e0e20b9a0bbc53525cb0cdc8537b8a631d262c14"},{"features":"Plain","commit":"0956eea613dafd1ed36626291a4bea327ef2175c78e9fe1826bac78e615a7c66fb"},{"features":"Plain","commit":"0939ea60b67648c4e505a4e5a6c579d1ea6f16d3245083b182e1d3893f845826da"}],"outputs":[{"features":"Plain","commit":"084d9026ac952e3125c7b700ba2ef5f8fc8b40c07faf7881be98abf2108cf8d3db","proof":"17cfa90c4def5dff0717d887f9db2edd36912632847b2d7986e93ab15e14c67b19b8cb012a9cf69e1bb76534b938180c5be5d4a8e9fd208f5bdf5470e550cb620b754a767553e439f3776fbc77e3268d827e3c7d5fe4f8927110ed6fec0854aa1f8cc81d5f11f9b142a31d017e0e4235296787015965e1f82a0bfc0687e71f70b919362d792344960e56f70a37c3d2e2d5864c10162966d254e80cdeddad8802dce063ce52437b067b3211cbb56055b4768df3a40f52703f1475b50481973f17cb3bd4a2e83a7ae601dcbc15b994b6bfd21455a3c439645b7e18ebed6e8172da1b5e1f98f21c95e661677bd5d7f832fbedd75b3963f79b49fa65728bef9d835967ef7654077731ed52b55bc8ecb462f3b53790fa3d2937f99e5d49a3b69e933fedf4b0be163d08661f7f9019b7998dffc05f492a4e908fa73da95da5cff4b5368afb036d70a0bcc32acc721beccb9f76e2cbea1b682d661aacb74a7b0683edb9bbc002b2661e7d03dd1f3ee0601a385298f0b9c52c3c6c21471bc894c8296826b4e284cf7d2c4660609368385e86d8cd4c3ab35f390dddf1e2d3537119fd58b63d8f42aba0594700eaf9bbcde3059ee047c59fd150b90a5c11af7a9b7df84ca9e7bdf7b2cb3e1eff0f57f03a93a60eb8b9e1e0b389c4d1ca8f276b122993d510da0e27cfdabb766e5be9470d271563ab5cd0e2f4ddbb680a27ec05b86e003fcc8dca9c0cf5a6bc4827e320d5956b6ee677a8874d5214313cb85834fa3e575bbcfe828940f049e1dd3c79cd1ee1a1d9c9a6f3df6f58c64b3b63afe7b23d4dcd00435c3450a85e31823582ae1714c6859d86f15cb56b92e37d86a4d0afb5af47b6dc94ebf26e59e5d97aa00f7bb44242b1fb54c4636d8ecc4bc93aba9fc02f1c8c9b2d7905c88bd4d340b1d7f44b5fe9bb970f1aa32ede88c4b3a7ecf59f4a2ad7cc672b"}],"kernels":[{"features":"HeightLocked","fee":"4000000","lock_height":"145202","excess":"000000000000000000000000000000000000000000000000000000000000000000","excess_sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}]}},"amount":"100000000","fee":"4000000","height":"145202","lock_height":"145202","participant_data":[{"id":"0","public_blind_excess":"03dc4bc089a2350ad9f7786fd45a37f3953ea3c707fbfa33886487f701de2245ba","public_nonce":"02caa967164f7ed74a9fd88d87c5bed9764b783d46e116b83417fe8ef4599c6c4d","part_sig":null,"message":null,"message_sig":null}]}</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/finalize_tx</td><td>Finalise and post transaction. Input is a respond slate. Transaction must belong to this wallet and can be finalized once.</td></tr>
  <tr><td colspan=2><code># curl -u mwc -X POST http://127.0.0.1:13415/v1/wallet/owner/finalize_tx -d '{"version_info": ......2d0ced60292d"}]}'</code></td></tr>
  <tr><td colspan=2><code>HTTP Code: 200 for success.</code></td></tr>
  <tr><td colspan=2><code>HTTP Code: 400 for failure: {"error": "error: failed finalizing slate!"} </code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>v1/wallet/owner/post_tx</td><td>Post transaction for the network. Input is a finalized slate. Slate can belong to any wallet, this commant just publish it. It can be used for cold wallet implementation.</td></tr>
  <tr><td colspan=2><code># curl -u mwc -X POST http://127.0.0.1:13415/v1/wallet/owner/post_tx -d '{"version_info": ......2d0ced60292d"}]}'</code></td></tr>
  <tr><td colspan=2><code>HTTP Code: 200 for success.</code></td></tr>
  <tr><td colspan=2><code>HTTP Code: 400 for failure: {"error": "Client Callback Error: Posting transaction to node: Request error: Wrong response code: 500 Internal Server Error with data Body(Streaming)"}</code></td></tr>
  <tr><td colspan=2><code>Note: this error mean that slate is most likely already published.
</code></td></tr>
</table>


### Foreign API Documentation

The foreign API must be configured on startup. The parameters which go into your mwc713.toml configuration file are as follows:

| parameter           | value  |
| ------------------- | ------ |
| foreign_api         | true   |
| foreign_api_address | The ip address:port to bind to for example: 127.0.0.1:13416. |
| foreign_api_secret  | The Basic Auth secret to connect to the owner API. |

A sample, configuration may look like this:

```
chain = "Floonet"
wallet713_data_path = "wallet713_data"
keybase_listener_auto_start = true
default_keybase_ttl = "24h"
foreign_api = true
foreign_api_address = "127.0.0.1:13416"
foreign_api_secret = "password"
```

Below is the documentation for the individual API end points:

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/foreign/build_coinbase</td><td>Build a coinbase output and insert into wallet.</td></tr>
  <tr><td colspan=2><code># curl  -u mwc -X POST http://127.0.0.1:13416/v1/wallet/foreign/build_coinbase -d '{"fees": 0, "height": 130} </code></td></tr>
  <tr><td colspan=2><code>{ "output": "010957734...b20e0d7efc",
    "kernel": "0100...02ca22",
    "key_id": "03000...00000"
}
</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/foreign/receive_tx</td><td>Recieve payload and generate the respond payload</td></tr>
  <tr><td colspan=2><code># curl -u mwc -X POST http://localhost:13416/v1/wallet/foreign/receive_tx -d '{"version_info": ......2d0ced60292d"}]}''</code></td></tr>
  <tr><td colspan=2><code>
    "version_info": {
        "version": 2,
        ........... 
            "message_sig": null
        }
    ]
}
</code></td></tr>
</table>


<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v2/foreign</td><td>Only receive_tx is supported at the moment, but this is enough to accept sends from mwc713 and mwc-wallet. Recieve invoice (initiated slate) generate the send payload back.</td></tr>
  <tr><td colspan=2><code># curl -u mwc -X POST http://localhost:13416/v2/foreign -d '{"id":1,"jsonrpc":"2.0","method":"receive_tx","params":[{"amount":"100000000","fee":"8000000","height":"152395","id":"99f01e25-6a6e-4151-8045-e818ae466a93","lock_height":"152395","num_participants":2,"participant_data":[{"id":"0","message":null,"message_sig":null,"part_sig":null,"public_blind_excess":"035c3ae42d3668065fe50caa466fec39c065777e5fa579116f77b39549d4bed362","public_nonce":"03b93371006c5dd1dd3c3242e22d00620a58ac8ee06f2d6742066ff93831f1b7e6"}],"tx":{"body":{"inputs":[{"commit":"09bef4bbbbd3bab2771de6f3c9321ddd118bdcd67f6f7f149b40829c4f16e1c228","features":"Plain"}],"kernels":[{"excess":"000000000000000000000000000000000000000000000000000000000000000000","excess_sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","features":"HeightLocked","fee":"8000000","lock_height":"152395"}],"outputs":[{"commit":"08b83d0b1f105bb342e789cf56f445fa5fdc053515c028e60748e1a6d25331a08a","features":"Plain","proof":"5546b90964f03210cf6e0787e5051d91b9da7a585f31ff84c7cc79983df77c6db55768dd45cead752f7da252f49602e9c63411124d7e15849701c11b56f7201d0bb1e0794eca3d675d5126eaddb8a496f85a829b3d92e9cc01bdd327d5c07bb9f48396e2ec3f99d3335f28b55131cba5dded691e69c118370f5a64dead36c7eda71fa956fb27d32a4b9638f8492d225586ba41626276617e7c4a9f5d27004d2d2d5984270a3fa1b3b44f118b0de3bf9a9e942fb8b8ba887ab0f45d2c034bd461316d1472372fc24b3fa94116007004baa0b3a9041331dc6938a9c839efc0024f0618d81e483c78b9c6a03b342b9cc7c37fd355b5f10a128a502fc3fc189a15d5e83e528f0f6fcb60196fd78523047931b214fe8e0f74f368629421ee0c5bf741beef936c61926e69789ad91a1f98b5c8a1992790c4157fbbe6121afe67c51b586d9d09e67a49c3c957f8de44b5e6af8bc78e2e678af480e74bb186927cfbc6d0d19b0321168673472983c4f28e32a922a6aef71f8df161ca41f3875fd5499fe4fa27198a404d8f4d54bc747357d61ed1741808e54ce13d07a868f62e693f94ec6b72d4c8005705a92129a49e3e3f17fbe880c163e9479683dd77aefc57fc6d9cc3c144b4f338f17196baab6393640cbdc9e9524cce343da0c98fd5f4c942dda6b266005c72cfb524576500ce8a3457803d6fdaf028ccb6b0c77c4c86f2b1dcab5c47b85244218203f6b18dbe959b92b7b6b7ea3e933ac6555b45e2a110832e7bb640cb90e62a0db9318cac26265aa3fb8027b44bc23b3f3d29161aa1ae6eabbd22dc4cef0fce59c9ff1b203adbe1bd1e92e735ed752df212b7bbf89451c9062485d172c5a4c1ee487c269ac7f079144f2baeb38832c40b835d8790e149c2de1d10465b2aedbaf5a7c9ec39428ddae9b2b05b3faed14d3eff4f518fa521327b69444ed2"}]},"offset":"1ade918f9adb43fa24551d5b5b4cf62c513ac29195e4a5c37ccb70c970fb92f6"},"version_info":{"block_header_version":1,"orig_version":2,"version":2}},null,null]}
'</code></td></tr>
  <tr><td colspan=2><code>
    "version_info": {
        "version": 2,
        ........... 
            "message_sig": null
        }
    ]
}
</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/foreign/receive_invoice</td><td>Recieve invoice (initiated slate) generate the send payload back. By default this feature disabled. Please check 'max_auto_accept_invoice' setting for more details.</td></tr>
  <tr><td colspan=2><code># curl -u mwc -X POST http://localhost:13416/v1/wallet/foreign/receive_invoice -d '{"version_info": ......2d0ced60292d"}]}''</code></td></tr>
  <tr><td colspan=2><code>
    "version_info": {
        "version": 2,
        ........... 
            "message_sig": null
        }
    ]
}
</code></td></tr>
</table>

### TODO

For owner API, we still need to implement account APIs. Currently only the default account is possible to use. We also should implement support for https send. We should also support TLS, which we currently don't. Also the foreign API will be enabled.
