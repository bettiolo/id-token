import crypto from 'crypto';
import assert from 'assert';
import jwt from 'jsonwebtoken';

// Based on https://tools.ietf.org/html/rfc7518#section-3.1
const algHashMapping = {
  'HS256': 'sha256',
  'HS384': 'sha384',
  'HS512': 'sha512',
  'RS256': 'sha256',
  'RS384': 'sha384',
  'RS512': 'sha512',
  // 'ES256': 'SHA256',
  // 'ES384': 'SHA384',
  // 'ES512': 'SHA512',
};

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

function computeHash(alg, accessTokenOrCode) {
  assert.ok(!!algHashMapping[alg],
    'Invalid algorithm');
  assert.ok(isNonEmptyString(accessTokenOrCode),
    'Argument "accessTokenOrCode" required (string)');

  // Implementation of Access Token hash (at_hash claim) or Code hash (c_hash claim)
  // http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
  const hash = crypto.createHash(algHashMapping[alg]);
  hash.update(accessTokenOrCode);
  const digest = hash.digest();
  const base64Hash = digest.toString('base64', 0, digest.length / 2);

  // Implementation of base64url Encoding without Padding
  // http://tools.ietf.org/html/rfc7515#appendix-C
  return base64Hash
    .split('=')[0] // Remove any trailing '='s
    .replace('+', '-') // 62nd char of encoding
    .replace('/', '_'); // 63rd char of encoding
}

export default {
  _computeHash: computeHash,

  createJwt(privatePem, claims = {},
    { expiresIn, accessToken, authorizationCode } = {}) {
    // Required parameters
    assert.ok(isPemRsaKey(privatePem),
      'argument "privatePem" must be a RSA Private Key (PEM)');

    // Options
    assert.ok(!accessToken || isNonEmptyString(accessToken),
      'option "accessToken" must be a string');
    assert.ok(!authorizationCode || isNonEmptyString(authorizationCode),
      'option "authorizationCode" must be a string');

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

    const options = {
      algorithm: alg,
      expiresIn,
      noTimestamp: !!claims.iat,
    };
    return jwt.sign(claims, privatePem, options);
  },
};
