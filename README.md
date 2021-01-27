## Installation

```shell
npm install git+https://github.com/the1337guy/libbetterauth
yarn add git+https://github.com/the1337guy/libbetterauth
```

## What & Why

This is an authentication toolkit to easily implement public-key authentication very easily and without baggage. With this, you can derive an Ed25519 key from a password, use that to sign all client-server requests and verify that the data is indeed from the claimed user.

Why? Storing a public key as opposed to a (hashed) password is a much better solution if you are concerned about security. This  also saves you from managing and saving tokens (say, something like JWT) for authentication and instead the password-derived private key is used to sign all requests without any token nonsense, the password is never stored in memory past the key-derivation phase and is kept secure.

I developed this library when I realized I was including the same authentication mechanism in every client-server software I was implementing.

## Usage

```javascript
// Generate private and public key from password
const { secretKey, publicKey } = await libbetterauth.generateKeyPairFromPW(password, salt)
// Store secretKey locally in memory or put that in localStorage or something
// Send publicKey via API or something

// Sign objects (client-side)
// NOTE: your_data is the payload
const signed = await libbetterauth.signObject(your_data, secretKey)

// Send signed over API and validate on server-side
// NOTE: I'm assuming in real life scenarios,
// the (claimed) ID of the user will be included in your_data and will be used in the server to look up the public key
const validated = await libbetterauth.verifyData(signed, publicKey)
// validated is either true or false
// If validated is true, we are sure that the data came from the user.
```

## How

PBKDF2 is used to derive a 32-byte seed from the supplied password and salt, which is in turn used to derive a 64-byte private key and 32-byte public key.

`signObject` (presumably used before every API request) adds a timestamp and signs the request with the private key. (`timestamp` is a Number  and `_sig` is the signature, base64-encoded)

`verifyData` (presumably used server-side for authentication) verifies whether the timestamp is in the last 5 minutes and then verifies whether the signature was made by the claimed user's public key.
