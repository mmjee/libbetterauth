const bodyParser = require('body-parser')
const msgpackr = require('msgpackr')
const omit = require('lodash.omit')

const { verifyData } = require('./index')

const rawParser = bodyParser.raw({
  type: 'application/x-libbetterauth-signed-msgpack'
})

module.exports = function (getUser, pickPublicKey) {
  return async function (req, res, next) {
    switch (req.method) {
      case 'POST':
      case 'PUT':
      case 'DELETE':
      case 'PATCH':
        if (req.headers['content-type'] !== 'application/x-libbetterauth-signed-msgpack') {
          next()
          return
        }
        try {
          await new Promise((resolve) => {
            return rawParser(req, res, resolve)
          })
          const decodedData = msgpackr.decode(req.body)
          const user = await getUser(decodedData.userID)
          if (!user) {
            // res.status(401).header('WWW-Authenticate', 'SignedMessage').send()
            res.status(401).send({
              error: true,
              errorCode: 'NO_USER_ID'
            })
            return
          }

          const pubKey = pickPublicKey(user)
          req.body = omit(verifyData(req.body, decodedData, pubKey), [
            'userID',
            'timestamp'
          ])

          req.user = user
          next()
        } catch (e) {
          res.status(401).send({
            error: true,
            errorCode: 'AUTHENTICATION_ERROR'
          })
        }
        break
      case 'GET':
      case 'HEAD': {
        const queryPos = req.originalUrl.indexOf('?')
        if (queryPos === -1) {
          next()
          return
        }
        // Skip the ?
        const queryString = req.originalUrl.slice(queryPos + 1)
        try {
          let buf, decoded
          try {
            buf = Buffer.from(queryString, 'base64url')
            decoded = msgpackr.decode(buf)
          } catch (e) {
            next()
            return
          }
          const user = await getUser(decoded.userID)
          if (!user) {
            res.status(401).send({
              error: true,
              errorCode: 'NO_USER_ID'
            })
            return
          }

          const pubKey = pickPublicKey(user)
          req.body = omit(verifyData(buf, decoded, pubKey), [
            'userID',
            'timestamp'
          ])

          req.user = user
        } catch (e) {
          res.status(401).send({
            error: true,
            errorCode: 'AUTHENTICATION_ERROR'
          })
        }
        break
      }
    }
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
