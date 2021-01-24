const { promisify } = require('util')
const { pbkdf2 } = require('crypto')
const tweetnacl = require('tweetnacl')

const toDate = require('date-fns/toDate')
const isAfter = require('date-fns/isAfter')
const sub = require('date-fns/sub')
const isString = require('lodash.isstring')
const omit = require('lodash.omit')

const pbkdf = promisify(pbkdf2)

class BetterAuthError extends Error {}
class InvalidDataError extends BetterAuthError {}

exports.BetterAuthError = BetterAuthError
exports.InvalidDataError = InvalidDataError

exports.generateKeyPairFromPW = async function generateKeyPairFromPW (pw, salt) {
  const {
    secretKey,
    publicKey
  } = await tweetnacl.sign.keyPair.fromSeed(await pbkdf(pw, salt, 10e5, 32, 'BLAKE2b512'))

  return {
    secretKey,
    publicKey: Buffer.from(publicKey).toString('base64')
  }
}

exports.generateRandomKP = function generateRandomKP () {
  return tweetnacl.sign.keyPair()
}

/*
 * Verifies the data that it indeed comes from key and the timestamp is within the past 5 minutes
 * @param {Object} data The user-supplied password
 * @returns {Object} The verified data
 */
exports.verifyData = function verifyData (data, key) {
  if (!Number.isFinite(data.timestamp)) {
    throw new InvalidDataError('Data has no timestamp')
  }
  if (!isString(data._sig) && data._sig.length !== 88) {
    throw new InvalidDataError('Data has no or invalid signature')
  }
  const fiveminuteago = sub(new Date(), {
    minutes: 5
  })
  // If signed timestamp is not within the past 5 minutes, throw error
  if (!isAfter(toDate(data.timestamp), fiveminuteago)) {
    throw new InvalidDataError('Data has expired signature')
  }

  const datawithoutsig = Buffer.from(JSON.stringify(omit(data, '_sig')))
  const akey = Buffer.from(key, 'base64')
  const sig = Buffer.from(data._sig, 'base64')

  return tweetnacl.sign.detached.verify(datawithoutsig, sig, akey)
}

/*
 * @param {Object} data Supplied data.
 * @param {Buffer} key Supplied key
 */
exports.signObject = function signObject (data, key) {
  data.timestamp = Date.now()
  const datawithoutsig = Buffer.from(JSON.stringify(data))
  const sig = tweetnacl.sign.detached(datawithoutsig, key)
  data._sig = Buffer.from(sig).toString('base64')
  return data
}
