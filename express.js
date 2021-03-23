const { verifyData } = require('./index')

module.exports = function (getUser, pickPublicKey) {
  return async function (req, res, next) {
    const { body } = req
    if (body._sig && body.timestamp && body.userID) {
      const user = await getUser(body.userID)
      if (!user) {
        // res.status(401).header('WWW-Authenticate', 'SignedMessage').send()
        res.status(401).send({
          error: true,
          errorMessage: 'NO_USER_ID'
        })
        return
      }
      const pubKey = pickPublicKey(user)
      const validated = verifyData(body, pubKey)
      if (!validated) {
        res.status(401).send({
          error: true,
          errorMessage: 'VERIFICATION_FAILED'
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
      errorMessage: 'AUTHENTICATION_MANDATORY'
    })
  } else {
    next()
  }
}
