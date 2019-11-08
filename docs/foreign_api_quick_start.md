As of mwc713 2.4.4, the foreign API is supported. Full documentation can be seen here: https://github.com/mwcproject/mwc713/blob/master/docs/API_documentation.md. 

Here we document a standard setup which may be useful.

1.) Obtain the latest binaries for mwc713: https://github.com/mwcproject/mwc713/releases.

2.) Unzip and ensure mwc713 is in your PATH.

3.) Make a directory in which your mwc713 install will reside:
```# mkdir mwc713_listener```

4.) Change directory to the directory:
```# cd mwc713_listener```

5.) Initialize your mwc713 listener (for main or floonet, if it's for main do not include the --floonet flag on this step)
```# mwc713 --floonet -c mwc713.config```

6.) Ensure that you are using at least mwc713 version 2.4.4 and select '1' to init the wallet. See screenshot.

![Install Wallet](https://raw.githubusercontent.com/mwcproject/mwc713/master/docs/init_mwc713.png "Install Wallet")

7.) Continue through the install process and exit:

```wallet713> exit```

8.) Modify your config file to look something like this:

```
# echo "chain = "Floonet"
wallet713_data_path = "wallet713_data"
keybase_binary = "keybase"
default_keybase_ttl = "24h"
foreign_api = true
foreign_api_address = "0.0.0.0:443"
tls_certificate_file = "/home/ubuntu/httpstest/mwc713/target/2/fullchain.pem"
tls_certificate_key = "/home/ubuntu/httpstest/mwc713/target/2/privkey.pem"" >> mwc713.config```


