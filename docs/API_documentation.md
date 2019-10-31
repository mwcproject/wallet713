# mwc713 API Documentation

### Overview

mwc713 supports both an 'Owner API' and a 'Foreign API'. The owner api controls functions that the owner of the wallet may only access and the foreign API is for receiving payments and invoices and may be accessed by the public.

### Owner API Documentation
<table>
  <tr><td>End Point</td><td>Description</td></tr>
  <tr><td>/v1/wallet/owner/node_height</td><td>Node height returns the number of blocks that is seen by the full node that this mwc713 instance is connected to.</td></tr>
  <tr><td colspan=2>```# curl http://localhost:13413/v1/owner/node_height```</td></tr>
  <tr><td colspan=2>```{"height": 173393}```</td></tr>
</table>
    

### Foreign API Documentation

### TODO
