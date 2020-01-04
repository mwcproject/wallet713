To verify funds from another mwc713 instance using mwc713, you need a file containing a single line in it which is the Extended
Public Key of the mwc713 instance you wish to verify. You can get the extended public key of your instance with the following
command:

```wallet713> getrootpublickey```

The output should look something like this:

```Root public key: 02fc38c51d3310a19488064438a038b4e6b33c5474618fbd053b7d7fc97831a6d3```


To verify (note: this can be done from any mwc713 instance) first save the pubkey to a text file with it's value as a single
line, then run the following command from mwc713:

```wallet713> scan_outputs -p /path/to/pubkey.txt```

This process will take a while because all UTXOs must be scanned, but when complete, a file will be created in the same directory as your pubkey file with the extension .commits. So in this case, the file would be saved at /path/to/pubkey.txt.commits.

The .commits file will look something like this:


```
PublicKey=02b46e34ec7b9cd770f406639b980e8319dbc89a5dd45c0bf6e493075e2db1fdcd Commit=08881b6238c232b34e6b5806d4a4e1c721ce443f06835f682c53343c6b09a8f167 amount=10255161848 height=120170 mmr_index=295668
PublicKey=02b46e34ec7b9cd770f406639b980e8319dbc89a5dd45c0bf6e493075e2db1fdcd Commit=085838487e4efccb81e47938c22a021d8dc567540922d420aa05b36324b0a5755f amount=66900000 height=195464 mmr_index=447068
PublicKey=02b46e34ec7b9cd770f406639b980e8319dbc89a5dd45c0bf6e493075e2db1fdcd Commit=0992501e3ad5c1cf224b79944b67d540b0e03ac07003b61734c92ae68373b3f533 amount=100000 height=195464 mmr_index=447069

```

Note that amounts are in nanomwc so in the above example, 10255161848 is equal to 10.255161848 MWC.
