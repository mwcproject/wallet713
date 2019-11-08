As of mwc713 2.4.4, the foreign API is supported. Full documentation can be seen here: https://github.com/mwcproject/mwc713/blob/master/docs/API_documentation.md. 

Here we document a standard setup which may be useful.

1.) Obtain the latest binaries for mwc713: https://github.com/mwcproject/mwc713/releases.

2.) Unzip and ensure mwc713 is in your PATH.

3.) Make a directory in which your mwc713 install will reside:
# mkdir mwc713_listener

4.) Change directory to the directory:
# cd mwc713_listener

5.) Initialize your mwc713 listener (for main or floonet, if it's for main do not include the --floonet flag on this step)
# mwc713 --floonet -c mwc713.config

6.) Ensure that you are using at least mwc713 version 2.4.4 and select '1' to init the wallet. See screenshot.
