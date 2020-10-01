# Example C++ Cryptographic Verification
This is an example of cryptographically verifying a license key's authenticity,
and extract embedded tamper-proof data within the key for offline use, all by
using your Keygen account's public key. You can find your public key within
[your account's settings page](https://app.keygen.sh/settings).

This example implements the [`RSA_2048_PKCS1_SIGN` scheme](https://keygen.sh/docs/api/#policies-create-attrs-scheme).
Cryptographically verifying schemed licenses can be used to implement
offline licensing, as well as to add additional security measures to
your licensing model. All that is needed to cryptographically verify
a license is your account's public key.

## Running the example

First up, add an environment variable containing your public key:
```bash
# Your Keygen account's public key (make sure it is *exact* - newlines and all)
export KEYGEN_PUBLIC_KEY=$(printf %b \
  '-----BEGIN PUBLIC KEY-----\n' \
  'zdL8BgMFM7p7+FGEGuH1I0KBaMcB/RZZSUu4yTBMu0pJw2EWzr3CrOOiXQI3+6bA\n' \
  # …
  'efK41Ml6OwZB3tchqGmpuAsCEwEAaQ==\n' \
  '-----END PUBLIC KEY-----')
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

Next, on macOS, install OpenSSL v1.0.2p using `homebrew`.
```bash
brew install openssl@1.0.2
```

Next, on macOS, compile the source using `g++`:
```bash
g++ main.cpp -o bin.out \
  -std=c++17 \
  -lssl \
  -lcrypto \
  -I /usr/local/opt/openssl/include \
  -L /usr/local/opt/openssl/lib
```

Then run the script, passing in the `key` as the first argument:
```bash
./bin.out "{KEYGEN_LICENSE_KEY}"
```

The license key's authenticity will be verified using RSA-SHA256 with PKCS1
v1.5 padding. Be sure to copy your public key and license key correctly - your
keys will fail validation if these are copied or included incorrectly. You can
find your public key in [your account's settings](https://app.keygen.sh/settings).

## Running on other platforms

We are only including instructions on how to compile and run this example on
macOS. If you'd like to create a PR with instructions for another platform,
such as Windows or Linux, please feel free to open a PR.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
