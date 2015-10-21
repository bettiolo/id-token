import jwt from 'jsonwebtoken';

export default {
  createJwt(privatePem) {

    var idToken = jwt.sign({}, privatePem, {
      algorithm: 'RS256',
    });

    return idToken;
  },
};
