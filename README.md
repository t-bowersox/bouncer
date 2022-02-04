# bouncer

A tool for checking user authorization.

## Installation

```bash
npm i @t-bowersox/bouncer
```

## Usage

Bouncer performs two primary sets of tasks:

- Issuing, revoking, & validating signed access tokens.
- Validating a user's attributes against a permissions ruleset.

### Requirements

In order to create a `Bouncer` instance, you must have the following:

- A private key string in PEM format.
- If your private key is encrypted by a passphrase, you must provide it as well.
- A public key string in PEM format.
- An object that implements the `TokenStore` interface.

Need help generating keys? [This article](https://www.scottbrady91.com/openssl/creating-rsa-keys-using-openssl) provides a good explainer using OpenSSL.

#### Token signing

The private and public keys are necessary for signing and verifying access tokens. Under the hood, Bouncer uses the Node.js [`crypto.createPrivateKey`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptocreateprivatekeykey) and [`crypto.createPublicKey`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptocreatepublickeykey) methods to create a `KeyObject` for each.

Those `KeyObject`s are used with instances of Node's [`Sign`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#class-sign) and [`Verify`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#class-verify) classes when signing and verifying access tokens, respectively. The algorithm used for signatures is SHA256.

The `Token` interface stores only a unique session ID, the user's ID, and an expiration timestamp. The session ID is generated using Node's [`crypto.randomUUID`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptorandomuuidoptions), which uses a cryptographic pseudorandom number generator.

#### Token stores

The `TokenStore` interface requires an object to have two methods that are used for tracking revoked tokens:

- `addToDenyList` - This is called by Bouncer to add a session ID to the "Deny List", which is a list of revoked tokens.
- `isOnDenyList` - This is called by Bouncer during token validation to see if a session ID has been revoked.

It is up to you to handle where to store the data, whether it's a key-value store, relational database, etc.

If you want to keep a dataset or log of all tokens issued by Bouncer, you will need to handle that yourself since it's outside the scope of what Bouncer's purpose.

