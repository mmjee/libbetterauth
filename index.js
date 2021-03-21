/*
    Copyright 2020, 2021 Maharshi Mukherjee
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
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

exports.generateKeyPairFromPW = async function generateKeyPairFromPW (pw, salt, {
  iterations = 10e5,
  hashAlgo = 'BLAKE2b512'
} = {}) {
  const {
    secretKey,
    publicKey
  } = await tweetnacl.sign.keyPair.fromSeed(await pbkdf(pw, salt, iterations, 32, hashAlgo))

  return {
    secretKey,
    publicKey
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
  const sig = Buffer.from(data._sig, 'base64')

  return tweetnacl.sign.detached.verify(datawithoutsig, sig, key)
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
