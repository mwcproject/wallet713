# mwc713 API Documentation

### Overview

mwc713 supports both an 'Owner API' and a 'Foreign API'. The owner api controls functions that the owner of the wallet may only access and the foreign API is for receiving payments and invoices and may be accessed by the public.

### Owner API Documentation
<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/node_height</td><td>Node height returns the number of blocks that is seen by the full node that this mwc713 instance is connected to.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/owner/node_height</code></td></tr>
  <tr><td colspan=2><code>{"height": 173393}</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/retrieve_summary_info</td><td>Summary info returns the same data that is returned when you run the info command from the command line interface of mwc713. This includes the height, total balance, balance awaiting confirmations, amount that is immature (mined mwc that is less than 1440 blocks old), spendable balance, and locked balance.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/owner/retrieve_summary_info</code></td></tr>
  <tr><td colspan=2><code>{"last_confirmed_height":145169,"minimum_confirmations":10,"total":30575500000,"amount_awaiting_confirmation":0,"amount_immature":0,"amount_currently_spendable":30575500000,"amount_locked":0}</code></td></tr>
</table>

<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/retrieve_outputs</td><td>This api retrieves the informations about the unspent outputs that are owned by this mwc713 instance. The response includes the root_key_id, key_id, n_child, commit, mmr_index (if applicable), value, status, height, lock_height, is_coinbase, and tx_log_entry for each unspent output in the wallet. It is returned in a json array.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/owner/retrieve_outputs</code></td></tr>
  <tr><td colspan=2><code>[false,[[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001ad00000000","n_child":429,"commit":"0939ea60b67648c4e505a4e5a6c579d1ea6f16d3245083b182e1d3893f845826da","mmr_index":null,"value":30575500000,"status":"Unspent","height":145016,"lock_height":0,"is_coinbase":false,"tx_log_entry":164},[9,57,234,96,182,118,72,196,229,5,164,229,166,197,121,209,234,111,22,211,36,80,131,177,130,225,211,137,63,132,88,38,218]]]]ChristophersMBP:mwc713 christophergilliard$ curl http://localhost:8889/v1/wallet/owner/retrieve_outputs
[false,[[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001ad00000000","n_child":429,"commit":"0939ea60b67648c4e505a4e5a6c579d1ea6f16d3245083b182e1d3893f845826da","mmr_index":null,"value":30575500000,"status":"Unspent","height":145016,"lock_height":0,"is_coinbase":false,"tx_log_entry":164},[9,57,234,96,182,118,72,196,229,5,164,229,166,197,121,209,234,111,22,211,36,80,131,177,130,225,211,137,63,132,88,38,218]],[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001b700000000","n_child":439,"commit":"093206e1f7b72205e8264ca2da1ae5459c1dfd0c0e9572ec7949e0d34d0974eea9","mmr_index":null,"value":5000000000,"status":"Unconfirmed","height":145187,"lock_height":0,"is_coinbase":false,"tx_log_entry":165},[9,50,6,225,247,183,34,5,232,38,76,162,218,26,229,69,156,29,253,12,14,149,114,236,121,73,224,211,77,9,116,238,169]],[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001b800000000","n_child":440,"commit":"0956eea613dafd1ed36626291a4bea327ef2175c78e9fe1826bac78e615a7c66fb","mmr_index":null,"value":5000000000,"status":"Unconfirmed","height":145187,"lock_height":0,"is_coinbase":false,"tx_log_entry":166},[9,86,238,166,19,218,253,30,211,102,38,41,26,75,234,50,126,242,23,92,120,233,254,24,38,186,199,142,97,90,124,102,251]],[{"root_key_id":"0200000000000000000000000000000000","key_id":"030000000000000000000001b900000000","n_child":441,"commit":"095899be912e0dc3d1635a6ff0adb79db1cbe2db75a01b175a39c64d45587716fd","mmr_index":null,"value":5000000000,"status":"Unconfirmed","height":145187,"lock_height":0,"is_coinbase":false,"tx_log_entry":167},[9,88,153,190,145,46,13,195,209,99,90,111,240,173,183,157,177,203,226,219,117,160,27,23,90,57,198,77,69,88,119,22,253]]]]</code></td></tr>
</table>

### Foreign API Documentation

### TODO
