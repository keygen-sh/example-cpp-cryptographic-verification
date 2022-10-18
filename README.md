# Example C++ Cryptographic Verification
This is an example of cryptographically verifying a license key's authenticity,
and extracting embedded tamper-proof data within the key for offline use, all by
using your Keygen account's public key. You can find your public key within
[your account's settings page](https://app.keygen.sh/settings).

This example implements the [`RSA_2048_PKCS1_SIGN_V2` scheme](https://keygen.sh/docs/api/#policies-create-attrs-scheme).
Cryptographically verifying schemed licenses can be used to implement
offline licensing, as well as to add additional security measures to
your licensing model. All that is needed to cryptographically verify
a license is your account's public key.

**No other `scheme` is supported.**

## Running the example

First up, add an environment variable containing your public key:

```bash
# Your Keygen account's base64-encoded RSA public key
export KEYGEN_PUBLIC_KEY="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6UEFzZURZdXBLNzhaVWFTYkd3NwpZeVVDQ2VLby8xWHFUQUNPY21UVEhIR2dlSGFjTEsyajlVcmJUbGhXNWg4VnlvMGlVRUhyWTFLZ2Y0d3dpR2dGCmgwWWMrb0RXRGhxMWJJZXJ0STAzQUU0MjBMYnBVZjZPVGlvWCtuWTBFSW54WEYzSjdhQWR4L1IvbllnUkpyTFoKOUFUV2FRVlNnZjN2dHhDdEN3VWVLeEtaSTQxR0EvOUtIVGNDbWQzQnJ5QVExcGlZUHIrcXJFR2YyTkRKZ3IzVwp2VnJNdG5qZW9vcmRBYUNUeVlLdGZtNTZXR1hlWHI0M2RmZGVqQnVJa0k1a3FTendWeW94aG5qRS9SajZ4a3M4CmZmSCtka0FQTndtMElweFhKZXJ5YmptUFd5djdpeVhFVU44Q0tHKzY0MzBEN05vWUhwL2M5OTFaSFFCVXM1OWcKdndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
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
  -stdlib=libc++ \
  -lssl \
  -lcrypto \
  -I /usr/local/opt/openssl/include \
  -L /usr/local/opt/openssl/lib \
  -I include/* \
  -g
```

Then run the script, passing in the `key` as the first argument:

```bash
./bin.out "key/xxxx.xxxx"
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
