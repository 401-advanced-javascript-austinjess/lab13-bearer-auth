'use strict';

const User = require('./users-model.js');
const _authBearer = (module.exports = (req, res, next) => {
  try {
    let [authType, authString] = req.headers.authorization.split(/\s+/);

    switch (authType.toLowerCase()) {
    case 'basic':
      return _authBasic(authString);
    case 'bearer':
      return _authBearer(authString);
    default:
      return _authError();
    }
  } catch (e) {
    next(e);
  }

  // Handle the Bearer Header to pull and verify with the token

  async function _authBearer(token) {
    console.log(`BEARER TOKEN: ${token}`);
    let user = await User.authenticateToken(token);
    await _authenticate(user);
  }

  function _authBasic(str) {
    // str: am9objpqb2hubnk=
    let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
    let bufferString = base64Buffer.toString(); // john:mysecret
    let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
    let auth = { username, password }; // { username:'john', password:'mysecret' }

    return User.authenticateBasic(auth)
      .then((user) => _authenticate(user))
      .catch(next);
  }

  function _authenticate(user) {
    console.log(user);
    if (!user) return _authError();
    req.user = user;
    req.token = user.generateToken();
    console.log(`TOKEN: ${req.token}`);
    next();
  }

  function _authError() {
    next({
      status: 401,
      statusMessage: 'Unauthorized',
      message: 'Invalid Username/Password',
    });
  }
});
