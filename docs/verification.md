To verify funds from another mwc713 instance using mwc713, you need a file containing a single line in it which is the Extended
Public Key of the mwc713 instance you wish to verify. You can get the extended public key of your instance with the following
command:

```wallet713> getrootpublickey```

The output should look something like this:

```Root public key: 02fc38c51d3310a19488064438a038b4e6b33c5474618fbd053b7d7fc97831a6d3```


To verify (note: this can be done from any mwc713 instance) first save the pubkey to a text file with it's value as a single
line, then run the following command from mwc713:

```wallet713> scan_outputs -p /path/to/pubkey.txt```

This process will take a while, but when complete, a file will be created in the same directory as your pubkey file with the
extension .commits. So in this case, the file would be saved at /path/to/pubkey.txt.commits.


