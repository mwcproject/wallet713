# Setting up MWC713

## Option 1: Using the official script

### Download and install latest version
From your terminal window run:
```
Download binaries from our releases page: https://github.com/cgilliard/mwc713/releases (available in Windows, Mac, and Linux)
```

### Run

Once installed, run wallet713 anywhere from your command prompt. You may need to restart your terminal window.
```
$ mwc713
```

If you'd like to run against floonet, use:
```
$ mwc713 --floonet
```
I

## Option 2: Building your own binary

### Requirements
1. All the [current requirements](https://github.com/mimblewimble/grin/blob/master/doc/build.md#requirements) of Grin.
1. [OpenSSL](https://www.openssl.org).
   * macOS with Homebrew:
      ```
      $ brew install openssl # you need to install version 1.1 of openssl for version 1.0.1 or newer of wallet713
      ``` 
   * Linux:
      ```
      $ sudo apt-get install openssl
      ```

### Installation

```
$ git clone https://github.com/cgilliard/mwc713
$ cd mwc713
$ cargo build --release
```
And then to run:
```
$ cd target/release
$ ./mwc713
```

If you'd like to run against floonet, use:
```
$ cd target/release
$ ./mwc713 --floonet
```
