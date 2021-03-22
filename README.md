## Installation

```shell
npm install git+https://github.com/mmjee/libbetterauth
yarn add git+https://github.com/mmjee/libbetterauth
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

// Sign objects (client-side) (your_data must contain userID if you want to make it compatible with the express middleware, see below)
// NOTE: your_data is the payload
const signed = await libbetterauth.signObject(your_data, secretKey)

// Send signed over API and validate on server-side
// NOTE: I'm assuming in real life scenarios,
const validated = await libbetterauth.verifyData(signed, publicKey)
// validated is either true or false
// If validated is true, we are sure that the data came from the user.
```

## How

PBKDF2 is used to derive a 32-byte seed from the supplied password and salt, which is in turn used to derive a 64-byte private key and 32-byte public key.

`signObject` (presumably used before every API request) adds a timestamp and signs the request with the private key. (`timestamp` is a Number  and `_sig` is the signature, base64-encoded)

`verifyData` (presumably used server-side for authentication) verifies whether the timestamp is in the last 5 minutes and then verifies whether the signature was made by the claimed user's public key.

## (semi)-opinionated express middleware

There's also an included express middleware to easily implement this server-side

```javascript
const betterAuthMiddleware = require('libbetterauth/express')

// Do this after you preferably include body-parser or an alternative
app.use(betterAuthMiddleware(/* getUser */ function (userID) {
  // The purpose of this function is to find a User object for the provided user ID (as transmitted in the user, MAY NOT BE CORRECT)
  return User.findById(userID) // You can also implement it like User.findOne({ email: userID }) if you are sure that email is a unique enough identifier
}, /* pickPublicKey */ function (user) {
  // The purpose of this function is to return the public key which you have stored in the user object
  return user.publicKey // or, user.pubkey, or user.pk, or... whatever
}))
// If authentication is MANDATORY, or otherwise req.user will only be available if authentication succeeds
app.use(betterAuthMiddleware.authenticationMandatory)
// In all subsequent middleware and route handlers, the user object will be available in req.user as returned by getUser
```
