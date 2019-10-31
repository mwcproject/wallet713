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
  <tr><td>/v1/wallet/owner/retrieve_outputs</td><td>This api retrieves the informations about the unspent outputs that are owned by this mwc713 instance.</td></tr>
  <tr><td colspan=2><code># curl -u mwc http://localhost:13415/v1/owner/retrieve_outputs</code></td></tr>
  <tr><td colspan=2><code>{"last_confirmed_height":145169,"minimum_confirmations":10,"total":30575500000,"amount_awaiting_confirmation":0,"amount_immature":0,"amount_currently_spendable":30575500000,"amount_locked":0}</code></td></tr>
</table>

### Foreign API Documentation

### TODO
