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

8.) Obtain a certificate and private key from a certificate authority. You may use certbot to do this in which case, the cert/privkey will be located in /etc/letsencrypt/live/<your_domain>/privkey.pem and /etc/letsencrypt/live/<your_domain>/fullchain.pem respectively. Note that the domain name must match the domain name you use to send your payments.

9.) Modify your mwc713.config file to look something like this:

```
chain = "Floonet"
wallet713_data_path = "wallet713_data"
keybase_binary = "keybase"
default_keybase_ttl = "24h"
foreign_api = true
foreign_api_address = "0.0.0.0:8443"
tls_certificate_file = "/path/to/certs/fullchain.pem"
tls_certificate_key = "/path/to/certs/privkey.pem"
```
Note: this install assumes you have keybase installed. If you do not have keybase installed and don't wish to support keybase, you can remove keybase_binary line above.

10.) Execute mwc713 with this configuration file.

```# mwc713 -c mwc713.config```

You will now have an mwc713 instance with the foreign listener listening for deposits. See screenshot.

![Listener Wallet](https://raw.githubusercontent.com/mwcproject/mwc713/master/docs/listening.png "Listener Wallet")

Before proceeding to verification, please ensure that firewalls are off and you can remotely access this port.

11.) Open another mwc713 instance in another terminal:

```# mwc713 --floonet```

12.) Send to the http listener with the following command:

``` wallet713> send --to https://myhost.com 0.1 -c 1 -g "hi there, message appears."```

13.) Go back to the terminal where you foreign API is running. You should see something like the screenshot below.

![Payment](https://raw.githubusercontent.com/mwcproject/mwc713/master/docs/payment.png "Payment")

Congratulations, you have configured the foreign API to accept incoming payments.

14.) Finally you may also send to this address using the mwc-qt-wallet GUI. See screenshot below.

![Payment2](https://raw.githubusercontent.com/mwcproject/mwc713/master/docs/qt.png "Payment2")

