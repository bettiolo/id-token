import assert from 'assert';
import jwt from 'jsonwebtoken';

function isRsaKey(pem) {
  return typeof (pem) === 'string'
    && pem.trimLeft().startsWith('-----BEGIN RSA PRIVATE KEY-----')
    && pem.trimRight().endsWith('-----END RSA PRIVATE KEY-----')
    && pem.trim().length > 60;
}

function isString(claim) {
  return typeof (claim) === 'string'
    && !!claim;
}

function isArrayOfStrings(claim) {
  return Array.isArray(claim)
    && claim.length > 0
    && claim.every(isString);
}

export default {
  createJwt(privatePem, claims = {}) {
    assert.ok(isRsaKey(privatePem),
      'argument "privatePem" must be a RSA Private Key (PEM)');
    assert.ok(isString(claims.iss) && !!claims.iss.trim(),
      'claim "iis" required (string)');
    assert.ok(isString(claims.sub) && claims.sub.length <= 255,
      'claim "sub" required (string, max 255 ASCII characters)');
    assert.ok(isString(claims.aud) || isArrayOfStrings(claims.aud),
      'claim "aud" required (string OR array of strings)');

    const options = {
      algorithm: 'RS256',
    };

    return jwt.sign(claims, privatePem, options);
  },
};
