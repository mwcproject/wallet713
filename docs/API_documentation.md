# mwc713 API Documentation

### Overview

mwc713 supports both an 'Owner API' and a 'Foreign API'. The owner api controls functions that the owner of the wallet may only access and the foreign API is for receiving payments and invoices and may be accessed by the public.

### Owner API Documentation

| End Point     | Description   |
| ------------- |---------------|
| /v1/wallet/owner/node_height      | Node height returns the number of blocks that is seen by the full node that this mwc713 instance is connected to. |
| ```# curl http://localhost:13413/v1/owner/node_height``` |
| ```{"height": 134}``` |
| /v1/wallet/owner/node_height      | description here |
| ```# curl http://localhost:13413/v1/owner/node_height``` |
| ```{"height": 134}``` |
| /v1/wallet/owner/node_height      | description here |
| ```# curl http://localhost:13413/v1/owner/node_height``` |
| ```{"height": 134}``` |

### Foreign API Documentation

### TODO
