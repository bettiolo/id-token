import assert from 'assert';
import jwt from 'jsonwebtoken';

function isRsaKey(pem) {
  return typeof (pem) === 'string'
    && pem.trimLeft().startsWith('-----BEGIN RSA PRIVATE KEY-----')
    && pem.trimRight().endsWith('-----END RSA PRIVATE KEY-----')
    && pem.trim().length > 60;
}

function isString(claim) {
  return typeof (claim) === 'string';
}

export default {
  createJwt(privatePem, claims = {}) {
    assert.ok(isRsaKey(privatePem),
      'argument "privatePem" must be a RSA Private Key (PEM)');
    assert.ok(isString(claims.iss) && !!claims.iss.trim(),
      'claim "iis" required (string)');
    assert.ok(isString(claims.sub) && claims.sub.length <= 255,
      'claim "sub" required (string, max 255 ASCII characters)');

    const options = {
      algorithm: 'RS256',
    };

    return jwt.sign(claims, privatePem, options);
  },
};
