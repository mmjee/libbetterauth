const libbetterauth = require('./index')

async function main () {
  const { secretKey, publicKey } = await libbetterauth.generateKeyPairFromPW('test', 'test')
  console.log('key:', secretKey, 'size:', secretKey.length)
  console.log('public:', publicKey, 'size:', publicKey.length)
  const signed = await libbetterauth.signObject({
    test: true
  }, secretKey)
  console.log('Signed message:', signed)
  const validated = await libbetterauth.verifyData(signed, publicKey)
  console.log('Validated:', validated)
}

main().catch(e => console.error(e))
