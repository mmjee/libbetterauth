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
const msgpackr = require('msgpackr')

const toDate = require('date-fns/toDate')
const isAfter = require('date-fns/isAfter')
const sub = require('date-fns/sub')

const pbkdf2Promisified = promisify(pbkdf2)

class BetterAuthError extends Error {}
class InvalidDataError extends BetterAuthError {}

exports.BetterAuthError = BetterAuthError
exports.InvalidDataError = InvalidDataError

exports.generateKeyPairFromPW = async function generateKeyPairFromPW (pw, salt, {
  iterations = 10e5,
  hashAlgo = 'sha512'
} = {}) {
  const {
    secretKey,
    publicKey
  } = await tweetnacl.sign.keyPair.fromSeed(await pbkdf2Promisified(pw, salt, iterations, 32, hashAlgo))

  return {
    secretKey: Buffer.from(secretKey),
    publicKey: Buffer.from(publicKey)
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
exports.verifyData = function verifyData (encodedData, decodedData, key) {
  const isSigValid = tweetnacl.sign.detached.verify(encodedData.slice(tweetnacl.sign.signatureLength), encodedData.slice(0, tweetnacl.sign.signatureLength), key)
  if (!isSigValid) {
    throw new InvalidDataError('Data has invalid signature')
  }

  if (!Number.isFinite(decodedData.timestamp)) {
    throw new InvalidDataError('Data has no timestamp')
  }
  const fiveminuteago = sub(new Date(), {
    minutes: 5
  })
  // If signed timestamp is not within the past 5 minutes, throw error
  if (!isAfter(toDate(decodedData.timestamp), fiveminuteago)) {
    throw new InvalidDataError('Data has expired signature')
  }

  return decodedData
}

/*
 * @param {Object} data Supplied data.
 * @param {Buffer} key Supplied key
 */
exports.signObject = function signObject (data, key) {
  data.timestamp = Date.now()
  const encoded = msgpackr.encode(data)

  const sig = tweetnacl.sign.detached(encoded, key)
  return Buffer.concat([sig, encoded])
}
