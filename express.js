const { verifyData } = require('./index')

module.exports = function (getUser, pickPublicKey) {
  return async function (req, res, next) {
    const { body } = req
    if (body._sig && body.timestamp && body.userID) {
      const user = await getUser(body.userID)
      if (!user) {
        // res.status(403).header('WWW-Authenticate', 'SignedMessage').send()
        res.status(401).send()
        return
      }
      const pubKey = pickPublicKey(user)
      const validated = verifyData(body, pubKey)
      if (!validated) {
        res.status(401).send()
        return
      }
      req.user = user
    }

    next()
  }
}

module.exports.authenticationMandatory = function (req, res, next) {
  if (!req.user) {
    res.status(403).send()
  } else {
    next()
  }
}
