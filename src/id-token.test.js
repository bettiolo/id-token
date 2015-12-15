import path from 'path';
import fs from 'fs';
import {assert} from 'chai';
import jwt from 'jsonwebtoken';
import idTokenWithoutDefaults from './id-token';
import getPem from 'rsa-pem-from-mod-exp';
import publicJwk from './test-data/test1-jwk.json';
import wrongPublicJwk from './test-data/test2-jwk.json';

const privatePemPath = path.join(__dirname, `./test-data/test1-private.pem`);
const privatePem = fs.readFileSync(privatePemPath, 'ascii');
const publicPem = getPem(publicJwk.n, publicJwk.e);
const wrongPublicPem = getPem(wrongPublicJwk.n, wrongPublicJwk.e);

describe('idToken', () => {
  const idToken = idTokenWithoutDefaults.withDefaults({
    options: {privatePem},
  });

  it(`Has expected methods`, () => {
    assert.isFunction(idToken.createJwt);
  });

  context(`${idToken.createJwt.name}()`, () => {
    const nowEpoch = Math.floor(Date.now() / 1000);
    const absoluteExpiryIn1Minute = nowEpoch + 60;
    const defaultClaims = {
      iss: 'http://example.com',
      sub: 'Abc123',
      aud: 'xyZ123',
      exp: absoluteExpiryIn1Minute,
    };

    it('Signs the token using RS256 algorithm', () => {
      const jwtIdToken = idToken.createJwt({claims: defaultClaims});
      const decodedIdToken = jwt.decode(jwtIdToken, {complete: true});

      assert.equal(decodedIdToken.header.alg, 'RS256');
    });

    it('Does not validate JWT ID Token with wrong RSA Public Key (PEM)', (done) => {
      const jwtIdToken = idToken.createJwt({claims: defaultClaims});
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
        idTokenWithoutDefaults.createJwt({claims: defaultClaims, options: {privatePem: invalidPem}}),
        'option "privatePem" must be a RSA Private Key (PEM)');
    });

    function itThrowsErrorWhenRequiredClaimMissing(claim, expectedError) {
      it(`Throws error when required claim "${claim}" missing`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        delete invalidClaims[claim];

        assert.throw(() => idToken.createJwt({claims: invalidClaims}), expectedError);
      });
    }

    function itThrowsErrorWhenClaimIsNotString(claim, expectedError) {
      it(`Throws error when claim "${claim}" not a string`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims[claim] = 12345;

        assert.throw(() => idToken.createJwt({claims: invalidClaims}), expectedError);
      });
    }

    function itThrowsErrorWhenClaimIsEmpty(claim, expectedError) {
      it(`Throws error when claim "${claim}" is empty`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims[claim] = '';

        assert.throw(() => idToken.createJwt({claims: invalidClaims}), expectedError);
      });
    }

    context('Claim "iis"', () => {
      itThrowsErrorWhenRequiredClaimMissing('iss',
        'claim "iis" required (string)');

      itThrowsErrorWhenClaimIsNotString('iss',
        'claim "iis" required (string)');

      itThrowsErrorWhenClaimIsEmpty('iss',
        'claim "iis" required (string)');

      it('Throws error when claim "iss" is invalid', () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims.iss = '   ';

        assert.throw(() => idToken.createJwt({claims: invalidClaims}),
          'claim "iis" required (string)');
      });

      it.skip('Throws error when claim "iss" contains query component', () => {
        assert.fail();
      });

      it.skip('Throws error when claim "iss" contains fragment component', () => {
        assert.fail();
      });
    });

    context('Claim "sub"', () => {
      itThrowsErrorWhenRequiredClaimMissing('sub',
        'claim "sub" required (string, max 255 ASCII characters)');

      itThrowsErrorWhenClaimIsEmpty('sub',
        'claim "sub" required (string, max 255 ASCII characters)');

      itThrowsErrorWhenClaimIsNotString('sub',
        'claim "sub" required (string, max 255 ASCII characters)');

      it('Throws error when claim "sub" exceeds 255 ASCII characters', () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims.sub = new Array(256 + 1).join('X');

        assert.throw(() => idToken.createJwt({claims: invalidClaims}),
          'claim "sub" required (string, max 255 ASCII characters)');
      });
    });

    context('Claim "aud"', () => {
      itThrowsErrorWhenRequiredClaimMissing('aud',
        'claim "aud" required (string OR array of strings)');

      itThrowsErrorWhenClaimIsEmpty('aud',
        'claim "aud" required (string OR array of strings)');

      itThrowsErrorWhenClaimIsNotString('aud',
        'claim "aud" required (string OR array of strings)');

      it('Claim "aud" can be an array of strings', () => {
        const claims = Object.assign({}, defaultClaims);
        claims.aud = ['Foo1', 'bar2'];

        const jwtIdToken = idToken.createJwt({claims});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.deepEqual(idTokenPayload.aud, ['Foo1', 'bar2']);
      });

      it('Throws error when required claim "aud" is an array with no elements', () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims.aud = [];

        assert.throw(() => idToken.createJwt({claims: invalidClaims}),
          'claim "aud" required (string OR array of strings)');
      });

      it('Throws error when required claim "aud" is an array of empty strings', () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims.aud = [''];

        assert.throw(() => idToken.createJwt({claims: invalidClaims}),
          'claim "aud" required (string OR array of strings)');
      });

      it('Throws error when claim "aud" not an array of strings', () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims.aud = [12345];

        assert.throw(() => idToken.createJwt({claims: invalidClaims}),
          'claim "aud" required (string OR array of strings)');
      });
    });

    function itThrowsErrorWhenClaimHasDecimalDigits(claim, expectedError) {
      it(`Throws error when claim "${claim}" has decimal digits`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims[claim] = 12345.67;

        assert.throw(() => idToken.createJwt({claims: invalidClaims}), expectedError);
      });
    }

    function itThrowsErrorWhenClaimIsNotNumber(claim, expectedError) {
      it(`Throws error when claim "${claim}" is not a number`, () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims[claim] = 'abc';

        assert.throw(() => idToken.createJwt({claims: invalidClaims}), expectedError);
      });
    }

    context('Claim "exp"', () => {
      itThrowsErrorWhenRequiredClaimMissing('exp',
        'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      it('Throws error when required claim "exp" is zero', () => {
        const invalidClaims = Object.assign({}, defaultClaims);
        invalidClaims.exp = 0;

        assert.throw(() => idToken.createJwt({claims: invalidClaims}),
          'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');
      });

      itThrowsErrorWhenClaimHasDecimalDigits('exp',
        'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      itThrowsErrorWhenClaimIsNotNumber('exp',
        'claim "exp" required (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      it('Ignores missing claim "exp" if option "expiresIn" is provided', () => {
        const claims = Object.assign({}, defaultClaims);
        delete claims.exp;
        const nowIn5MinutesEpoch = Math.floor(Date.now() / 1000) + (5 * 60) + 1;

        const jwtIdToken = idToken.createJwt({claims, options: {expiresIn: '5m'}});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.ok(idTokenPayload.exp > nowEpoch);
        assert.ok(idTokenPayload.exp > absoluteExpiryIn1Minute);
        assert.ok(idTokenPayload.exp < nowIn5MinutesEpoch);
      });

      it('Throws error because claim "exp" and parameter "expiresIn" are mutually exclusive', () => {
        assert.throw(() => idToken.createJwt({claims: defaultClaims, options: {expiresIn: '5m'}}),
          'claim "exp" and parameter expiresIn are mutually exclusive');
      });
    });

    context('Auto-generated claim "iat"', () => {
      itThrowsErrorWhenClaimHasDecimalDigits('iat',
        'claim "iat" optional (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      itThrowsErrorWhenClaimIsNotNumber('iat',
        'claim "iat" optional (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      it('Claim "iat" can be overriden', () => {
        const claims = Object.assign({}, defaultClaims);
        claims.iat = 1311280970;
        const jwtIdToken = idToken.createJwt({claims});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.equal(idTokenPayload.iat, 1311280970);
      });
    });

    it('Creates a signed JWT ID Token with RSA Private Key (PEM)', () => {
      const jwtIdToken = idToken.createJwt({claims: defaultClaims});
      const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

      assert.isObject(idTokenPayload);
      assert.equal(idTokenPayload.iss, 'http://example.com');
      assert.equal(idTokenPayload.sub, 'Abc123');
      assert.equal(idTokenPayload.aud, 'xyZ123');
      assert.ok(idTokenPayload.exp > nowEpoch);
      assert.ok(idTokenPayload.iat >= nowEpoch);
      assert.ok(idTokenPayload.iat < idTokenPayload.exp);
    });

    function itIgnoresMissingOptionalClaim(claim) {
      it(`It ignores missing optional claim "${claim}"`, () => {
        const claims = Object.assign({}, defaultClaims);
        delete claims[claim];

        const jwtIdToken = idToken.createJwt({claims});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.ok(!idTokenPayload[claim]);
      });
    }

    context('Optional claim "auth_time"', () => {
      itIgnoresMissingOptionalClaim('auth_time');

      itThrowsErrorWhenClaimHasDecimalDigits('auth_time',
        'claim "auth_time" optional (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      itThrowsErrorWhenClaimIsNotNumber('auth_time',
        'claim "auth_time" optional (number of seconds from 1970-01-01T00:00:00Z in UTC)');

      it('Creates a signed JWT ID Token with optional "auth_time" claim', () => {
        const claims = Object.assign(defaultClaims, {
          auth_time: nowEpoch,
          nonce: 'vr2MrVSjyfu0UbrOtjWG',
        });
        const jwtIdToken = idToken.createJwt({claims});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.equal(idTokenPayload.iss, 'http://example.com');
        assert.equal(idTokenPayload.auth_time, nowEpoch);
        assert.equal(idTokenPayload.nonce, 'vr2MrVSjyfu0UbrOtjWG');
      });
    });

    context('Optional claim "nonce"', () => {
      itIgnoresMissingOptionalClaim('nonce');

      itThrowsErrorWhenClaimIsNotString('nonce',
        'claim "nonce" optional (string)');

      it('Creates a signed JWT ID Token with optional "nonce" claim', () => {
        const claims = Object.assign(defaultClaims, {
          nonce: 'vr2MrVSjyfu0UbrOtjWG',
        });
        const jwtIdToken = idToken.createJwt({claims});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.equal(idTokenPayload.iss, 'http://example.com');
        assert.equal(idTokenPayload.auth_time, nowEpoch);
        assert.equal(idTokenPayload.nonce, 'vr2MrVSjyfu0UbrOtjWG');
      });
    });

    function itThrowsErrorWhenOptionIsNotString(option, expectedError) {
      it(`Throws error when option "${option}" not a string`, () => {
        const options = {
          privatePem,
          [option]: 12345,
        };
        assert.throw(() => idToken.createJwt({claims: defaultClaims, options}), expectedError);
      });
    }

    context('Optional claim "at_hash"', () => {
      itThrowsErrorWhenOptionIsNotString('accessToken',
        'option "accessToken" must be a string');

      it('Creates a signed JWT ID Token with "at_hash" option', () => {
        const options = {accessToken: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'};
        const jwtIdToken = idToken.createJwt({claims: defaultClaims, options});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.equal(idTokenPayload.at_hash, '77QmUPtjPfzWtF2AnpK9RQ');
      });
    });

    context('Optional claim "c_hash"', () => {
      itThrowsErrorWhenOptionIsNotString('authorizationCode',
        'option "authorizationCode" must be a string');

      it('Creates a signed JWT ID Token with "c_hash" option', () => {
        const options = {authorizationCode: 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk'};
        const jwtIdToken = idToken.createJwt({claims: defaultClaims, options});
        const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {algorithms: ['RS256']});

        assert.isObject(idTokenPayload);
        assert.equal(idTokenPayload.c_hash, 'LDktKdoQak3Pk0cnXxCltA');
      });
    });

    context('Optional header parameter "kid', () => {
      itThrowsErrorWhenOptionIsNotString('kid',
        'option "kid" must be a string');

      it('Creates a JWT ID Token with the "kid" header parameter', () => {
        const options = {kid: '12345abc'};
        const jwtIdToken = idToken.createJwt({claims: defaultClaims, options});
        const decodedIdToken = jwt.decode(jwtIdToken, {complete: true});

        assert.equal(decodedIdToken.header.kid, '12345abc');
      });
    });

    context('Other claims', () => {
      it.skip('Other claims are ignored');
    });

    context('Other header parameter', () => {
      it.skip('Other header parameters are ignored');
    });
  });
});
