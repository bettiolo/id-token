import assert from 'assert';
import crypto from 'crypto';

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
function isNonEmptyString(value) {
  return typeof (value) === 'string'
    && !!value;
}

export default function computeHash(alg, accessTokenOrCode) {
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
