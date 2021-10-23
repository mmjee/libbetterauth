const _isString = require('lodash.isstring')
const _omit = require('lodash.omit')
const { verifyData } = require('./index')

const FIELDS_TO_OMIT = [
  'userID',
  'timestamp'
]

module.exports = function (getUser, pickPublicKey) {
  return async function (req, res, next) {
    let body

    const sig = req.get('Authorization')
    if (sig != null) {
      switch (req.method) {
        case 'GET':
        case 'HEAD':
          body = req.query
          body.timestamp = Number(body.timestamp)
          break
        default:
          body = req.body
          break
      }
    } else {
      return next()
    }

    if (!_isString(body.userID)) {
      return next()
    }

    const user = await getUser(body.userID)
    if (!user) {
      // res.status(401).header('WWW-Authenticate', 'SignedMessage').send()
      res.status(401).send({
        error: true,
        errorCode: 'NO_USER_ID'
      })
      return
    }

    const pubKey = pickPublicKey(user)
    let validated = false
    try {
      validated = verifyData(body, sig, pubKey)
    } catch (e) {
      console.warn('libbetterauth: Caught error at verifyData', e)
    }
    if (!validated) {
      res.status(401).send({
        error: true,
        errorCode: 'VERIFICATION_FAILED'
      })
      return
    }

    switch (req.method) {
      case 'GET':
      case 'HEAD':
        req.query = _omit(req.query, FIELDS_TO_OMIT)
        break
      default:
        req.body = _omit(req.body, FIELDS_TO_OMIT)
        break
    }

    req.user = user
    next()
  }
}

module.exports.authenticationMandatory = function (req, res, next) {
  if (!req.user) {
    res.status(403).send({
      error: true,
      errorCode: 'AUTHENTICATION_MANDATORY'
    })
  } else {
    next()
  }
}
