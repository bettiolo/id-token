import assert from 'assert';
import jwt from 'jsonwebtoken';
import computeHash from './compute-hash';

// TODO: We may need to implement more additional valid options:
// http://stackoverflow.com/a/20065554/26754
function isPemRsaKey(pem) {
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

function createJwt({claims = {}, options: {privatePem, expiresIn, accessToken, authorizationCode, kid} = {}}) {
  // Required parameters
  assert.ok(isPemRsaKey(privatePem),
    'option "privatePem" must be a RSA Private Key (PEM)');

  // Options
  assert.ok(!accessToken || isNonEmptyString(accessToken),
    'option "accessToken" must be a string');
  assert.ok(!authorizationCode || isNonEmptyString(authorizationCode),
    'option "authorizationCode" must be a string');
  assert.ok(!kid || isNonEmptyString(kid),
    'option "kid" must be a string');

  // Required ID Token claims
  // http://openid.net/specs/openid-connect-core-1_0.html#IDToken
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

  // Optional ID Token claims
  // http://openid.net/specs/openid-connect-core-1_0.html#IDToken
  assert.ok(!claims.iat || isPositiveInteger(claims.iat),
    'claim "iat" optional (number of seconds from 1970-01-01T00:00:00Z in UTC)');
  assert.ok(!claims.auth_time || isPositiveInteger(claims.auth_time),
    'claim "auth_time" optional (number of seconds from 1970-01-01T00:00:00Z in UTC)');
  assert.ok(!claims.nonce || isNonEmptyString(claims.nonce),
    'claim "nonce" optional (string)');

  const alg = 'RS256';

  if (accessToken) {
    claims.at_hash = computeHash(alg, accessToken);
  }
  if (authorizationCode) {
    claims.c_hash = computeHash(alg, authorizationCode);
  }

  return jwt.sign(claims, privatePem, {
    algorithm: alg,
    expiresIn,
    noTimestamp: !!claims.iat,
    headers: {kid},
  });
}

export default {
  createJwt,
  withDefaults: (defaults = {}) => ({
    createJwt: ({claims, options}) => createJwt({
      claims: Object.assign({}, defaults.claims, claims),
      options: Object.assign({}, defaults.options, options),
    }),
  }),
};
