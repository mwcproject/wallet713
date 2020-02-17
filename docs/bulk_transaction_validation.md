# mwc713 transaction validation in bulk

# Overview

Normally transactions that was made through MWC MQS can be validated manually on the MWC blockchain through the block explorer. However, for users with many transactions, it may be time consuming to validate many transactions manually.

This feature allows one to validate all input/outputs transactions by checking if this transaction was delivered to the blockchain in bulk.

Currently this method is not designed for everyday usage, because kernels snapshot made manually by request. But this can be done by users through data available in the full node if desired.

# How it works

Every transaction has kernel that has to be written into the blockchain even if all transaction input/output commits was cut through.
In order to validate transaction we need check if the kernel exist at the block chain at the **FULL** node.

# Workflow

### Get Blockchain transactions kernels data.

Kernels data is normally available at http://ftp.mwc.mw/kernel_dumps.tar.gz

But please undersatnd that it is updated by request only. In case if you need to validate all your transactions, please ask developers for a fresh snapshot.

Please download the data from that link, unzip the files. You should be able to see two files inside: kerneldump.txt for mainnet and kerneldump_floonet.txt for floonet.

Files formal is a plain text. Every line contain the single kernel.


### Validate transactions

Please note that the following command is only available as of mwc713 3.0.0-beta.1: https://github.com/mwcproject/mwc713/releases/tag/3.0.0-beta.1

To validate transactions please use the command

```
txs-bulk-validate
validate current account transactions against the full node data dump. In order to do that you should get a kernels dump
frm the full node (regular node can't be used for that). If you have few transactions you can validate transaction
proofs manually.

USAGE:
    txs-bulk-validate [OPTIONS]

OPTIONS:
    -k, --kernels <file>    file name with transaction kernels from the full node
    -r, --result <file>     resulting file with transactions in CVS format. Last column the result of validation
```


1. Run your mwc713 wallet, unlock it.

2. Select account with transactions that you want to validate.

3. Run the command:

```
txs-bulk-validate -k /Users/bay/Downloads/kernel_dumps/kerneldump_floonet.txt -r /tmp/transactions.txt
Please check results in CSV format at /tmp/transactions.txt
``` 

4. Resulting file will be written in CSV format. You can open /tmp/transactions.txt  with Excel and process it according your needs.

### Export Columns

 * id   - Transaction ID, zero based transaction index as mwc713 show for 'txs' command.
 * uuid - Full transaction (slate) UUID. Please note mwc713 show first 8 symbols of uuid.
 * type - Transaction type: one of Coinbase, Received, Sent, ReceivedCancelled, SentCancelled.
 * address - Transaction address if known.
 * Create Time - When transaction was created (not confirmed).
 * Height  - Transaction height if known.
 * Amount - Transaction amount.
 * Fee  - Fee amount if known.
 * Message - Messages that transaction parties put there.
 * node validation - Result of validation with the node. True if transaction was saved at the blockchain. False if transaction was not saved at the network.
