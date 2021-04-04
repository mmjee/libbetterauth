const isString = require('lodash.isstring')
const omit = require('lodash.omit')
const { verifyData } = require('./index')

module.exports = function (getUser, pickPublicKey) {
  return async function (req, res, next) {
    let body
    if (req.body._sig && req.body.timestamp && req.body.userID) {
      body = req.body
      req.body = omit(body, [
        '_sig',
        'timestamp',
        'userID'
      ])
    } else if (req.query._sig && req.query.timestamp && req.query.userID) {
      body = req.query
      if (isString(body.timestamp)) {
        body.timestamp = Number(body.timestamp)
      }
      req.query = omit(body, [
        '_sig',
        'timestamp',
        'userID'
      ])
    }
    if (body) {
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
        validated = verifyData(body, pubKey)
      } catch (e) {
        throw e
        // TODO handle statistics?
      }
      if (!validated) {
        res.status(401).send({
          error: true,
          errorCode: 'VERIFICATION_FAILED'
        })
        return
      }
      req.user = user
    }

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
