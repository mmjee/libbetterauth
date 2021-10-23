const isString = require('lodash.isstring')
const { verifyData } = require('./index')

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

    if (!isString(body.userID)) {
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
      validated = verifyData(body, pubKey, sig)
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
