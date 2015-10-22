import assert from 'assert';
import jwt from 'jsonwebtoken';

export default {
  createJwt(privatePem, claims = {}) {
    assert.ok(typeof (privatePem) === 'string'
      && privatePem.trimLeft().startsWith('-----BEGIN RSA PRIVATE KEY-----')
      && privatePem.trimRight().endsWith('-----END RSA PRIVATE KEY-----')
      && privatePem.trim().length > 60,
      'argument "privatePem" must be a RSA Private Key (PEM)');
    assert.ok(typeof (claims.iss) === 'string'
      && !!claims.iss.trim(),
      'claim "iis" required (string)');

    const options = {
      algorithm: 'RS256',
      issuer: claims.iss,
    };

    delete claims.iss;

    return jwt.sign(claims, privatePem, options);
  },
};
