import path from 'path';
import fs from 'fs';
import { assert } from 'chai';
import jwt from 'jsonwebtoken';
import idToken from './id-token';
import getPem from 'rsa-pem-from-mod-exp';
import publicJwk from '../../test/data/test1-jwk.json';
import wrongPublicJwk from '../../test/data/test2-jwk.json';

const privatePemPath = path.join(__dirname, `../../test/data/test1-private.pem`);
const privatePem = fs.readFileSync(privatePemPath, 'ascii');
const publicPem = getPem(publicJwk.n, publicJwk.e);
const wrongPublicPem = getPem(wrongPublicJwk.n, wrongPublicJwk.e);

describe('idToken', () => {
  it('Has createJwt method', () => {
    assert.isFunction(idToken.createJwt);
  });

  context('create()', () => {
    const nowEpoch = Math.floor(Date.now() / 1000);
    const absoluteExpiryIn1Minute = nowEpoch + 60;

    const defaultClaims = {
      iss: 'http://example.com',
      sub: 'Abc123',
      aud: 'xyZ123',
      exp: absoluteExpiryIn1Minute,
    };

    function itThrowsErrorWhenRequiredClaimMissing(claim, expectedError) {
      it(`Throws error when required claim "${claim}" missing`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        delete invalidClaims[claim];

        assert.throw(() => idToken.createJwt(privatePem, invalidClaims), expectedError);
      });
    }

    function itThrowsErrorWhenClaimIsNotAString(claim, expectedError) {
      it(`Throws error when claim "${claim}" not a string`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims[claim] = 12345;

        assert.throw(() => idToken.createJwt(privatePem, invalidClaims), expectedError);
      });
    }

    function itThrowsErrorWhenClaimIsEmpty(claim, expectedError) {
      it(`Throws error when claim "${claim}" is empty`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims[claim] = '';

        assert.throw(() => idToken.createJwt(privatePem, invalidClaims), expectedError);
      });
    }

    it('Creates a JWT Token', () => {
      const jwtIdToken = idToken.createJwt(privatePem, defaultClaims);

      assert.isString(jwtIdToken);
    });

    it('Signs the token using RS256 algorithm', () => {
      const jwtIdToken = idToken.createJwt(privatePem, defaultClaims);
      const decodedIdToken = jwt.decode(jwtIdToken, { complete: true });

      assert.equal(decodedIdToken.header.alg, 'RS256');
    });

    it('Creates a signed JWT ID Token with RSA Private Key (PEM)', () => {
      const jwtIdToken = idToken.createJwt(privatePem, defaultClaims);
      const idTokenPayload = jwt.verify(jwtIdToken, publicPem, { algorithms: ['RS256'] });

      assert.isObject(idTokenPayload);
      assert.equal(idTokenPayload.iss, 'http://example.com');
      assert.equal(idTokenPayload.sub, 'Abc123');
      assert.equal(idTokenPayload.aud, 'xyZ123');
      assert.ok(idTokenPayload.exp > nowEpoch);
      // TODO: Check al the claims
    });

    it('Does not validate JWT ID Token with wrong RSA Public Key (PEM)', (done) => {
      const jwtIdToken = idToken.createJwt(privatePem, defaultClaims);
      jwt.verify(jwtIdToken, wrongPublicPem, defaultClaims, (err, idTokenPayload) => {
        assert.isUndefined(idTokenPayload);
        assert.equal(err.message, 'invalid signature');
        done();
      });
    });

    it('Throws error when RSA Private Key (PEM) invalid', () => {
      const invalidPem =
        '-----BEGIN RSA PRIVATE KEY-----' +
        '-----END RSA PRIVATE KEY-----';
      assert.throw(() =>
        idToken.createJwt(invalidPem, defaultClaims),
        'argument "privatePem" must be a RSA Private Key (PEM)');
    });

    itThrowsErrorWhenRequiredClaimMissing('iss',
      'claim "iis" required (string)');

    itThrowsErrorWhenClaimIsNotAString('iss',
      'claim "iis" required (string)');

    itThrowsErrorWhenClaimIsEmpty('iss',
      'claim "iis" required (string)');

    it('Throws error when claim "iss" is invalid', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.iss = '   ';

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "iis" required (string)');
    });

    it.skip('Throws error when claim "iss" contains query component', () => {
      assert.fail();
    });

    it.skip('Throws error when claim "iss" contains fragment component', () => {
      assert.fail();
    });

    itThrowsErrorWhenRequiredClaimMissing('sub',
      'claim "sub" required (string, max 255 ASCII characters)');

    itThrowsErrorWhenClaimIsEmpty('sub',
      'claim "sub" required (string, max 255 ASCII characters)');

    itThrowsErrorWhenClaimIsNotAString('sub',
      'claim "sub" required (string, max 255 ASCII characters)');

    it('Throws error when claim "sub" exceeds 255 ASCII characters', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.sub = new Array(256 + 1).join('X');

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "sub" required (string, max 255 ASCII characters)');
    });

    itThrowsErrorWhenRequiredClaimMissing('aud',
      'claim "aud" required (string OR array of strings)');

    itThrowsErrorWhenClaimIsEmpty('aud',
      'claim "aud" required (string OR array of strings)');

    itThrowsErrorWhenClaimIsNotAString('aud',
      'claim "aud" required (string OR array of strings)');

    it('Claim "aud" can be an array of strings', () => {
      const claims = Object.assign({}, defaultClaims);
      claims.aud = ['Foo1', 'bar2'];

      const jwtIdToken = idToken.createJwt(privatePem, claims);
      const idTokenPayload = jwt.verify(jwtIdToken, publicPem, { algorithms: ['RS256'] });

      assert.deepEqual(idTokenPayload.aud, ['Foo1', 'bar2']);
    });

    it('Throws error when required claim "aud" is an array with no elements', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.aud = [];

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "aud" required (string OR array of strings)');
    });

    it('Throws error when required claim "aud" is an array of empty strings', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.aud = [''];

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "aud" required (string OR array of strings)');
    });

    it('Throws error when claim "aud" not an array of strings', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.aud = [ 12345 ];

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "aud" required (string OR array of strings)');
    });

    itThrowsErrorWhenRequiredClaimMissing('exp',
      'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');

    it('Throws error when required claim "exp" is zero', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.exp = 0;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');
    });

    it('Throws error when required claim "exp" has decimal digits', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.exp = 12345.67;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');
    });

    it('Throws error when required claim "exp" is not a number', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.exp = 'abc';

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');
    });

    // TODO: Test that "exp" claim is bigger than "iat"
  });
});
