# Sample Java implementation of Privacy Pass

WARNING: This is NOT meant for production use, has not been audited, may contain bugs, etc. Use at your own risk. 

This repository contains Java bindings to [this native blind RSA implementation](https://github.com/jedisct1/blind-rsa-signatures), as well as a simple Privacy Pass client that uses these functions to run the Privacy Pass [issuance protocol](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html). The purpose is to demonstrate how one might implement the Privacy Pass protocol in Java using an existing Blind RSA implementation. It almost certainly can be improved (for instance, there are no tests).

This repository does NOT contain an implementation of the [challenge or redemption protocols](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-auth-scheme.html). These are trivial to implement, though, and might be added in time.

## Build instructions

```
$ javac -cp "json.jar:" -h . PrivacyPassExample.java
$ javac -cp "json.jar:" PrivacyPassExample.java
$ make shim
```

## Run instructions

The client in this repository interoperates with the [reference issuer provided in this repository](https://github.com/cloudflare/pat-app). To run them, do the following:

1. Clone the [pat-app](https://github.com/cloudflare/pat-app) repository and patch it so that the issuer does not require TLS. (There is probably a way to modify the Java TLS trust anchor, but I didn't look very hard to do this.)
2. Run the issuer via `make issuer`
3. Run the client via `json.jar:" PrivacyPassExample`.

That's it! If everything works, you should see no output. If there's an error, an exception will be tossed and printed to the console.
