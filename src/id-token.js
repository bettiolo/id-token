import assert from 'assert';
import jwt from 'jsonwebtoken';

function isRsaKey(pem) {
  return typeof (pem) === 'string'
    && pem.trimLeft().startsWith('-----BEGIN RSA PRIVATE KEY-----')
    && pem.trimRight().endsWith('-----END RSA PRIVATE KEY-----')
    && pem.trim().length > 60;
}

function isNonEmptyString(value) {
  return typeof (value) === 'string'
    && !!value;
}

function isPositiveInteger(number) {
  return typeof (number) === 'number'
    && number > 0
    && number % 1 === 0;
}

function isArrayOfStrings(array) {
  return Array.isArray(array)
    && array.length > 0
    && array.every(isNonEmptyString);
}

export default {
  createJwt(privatePem, claims = {}, expiresIn) {
    assert.ok(isRsaKey(privatePem),
      'argument "privatePem" must be a RSA Private Key (PEM)');
    assert.ok(isNonEmptyString(claims.iss) && !!claims.iss.trim(),
      'claim "iis" required (string)');
    assert.ok(isNonEmptyString(claims.sub) && claims.sub.length <= 255,
      'claim "sub" required (string, max 255 ASCII characters)');
    assert.ok(isNonEmptyString(claims.aud) || isArrayOfStrings(claims.aud),
      'claim "aud" required (string OR array of strings)');
    assert.ok(isPositiveInteger(claims.exp) || !!expiresIn,
      'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');
    assert.ok(!(claims.exp && expiresIn),
      'claim "exp" and parameter expiresIn are mutually exclusive');

    const options = {
      algorithm: 'RS256',
      expiresIn,
    };

    return jwt.sign(claims, privatePem, options);
  },
};
