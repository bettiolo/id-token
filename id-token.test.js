import path from 'path';
import fs from 'fs';
import { assert } from 'chai';
import jwt from 'jsonwebtoken';
import idToken from './id-token';
const privatePemPath = path.join(__dirname, `../../test/data/test1-private.pem`);
import getPem from 'rsa-pem-from-mod-exp';
import publicJwk from '../../test/data/test1-jwk.json';
import wrongPublicJwk from '../../test/data/test2-jwk.json';

const privatePem = fs.readFileSync(privatePemPath, 'ascii');
const publicPem = getPem(publicJwk.n, publicJwk.e);
const wrongPublicPem = getPem(wrongPublicJwk.n, wrongPublicJwk.e);

describe('idToken', () => {
  it('Has createJwt method', () => {
    assert.isFunction(idToken.createJwt);
  });

  context('#create', () => {
    const defaultClaims = {
      iss: 'http://example.com',
      sub: 'Abc123',
    };

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
      assert.equal(idTokenPayload.iss, defaultClaims.iss);
      // TODO: add more checks
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

    it('Throws error when claim "iss" missing', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      delete invlidClaims.iss;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "iis" required (string)');
    });

    it('Throws error when claim "iss" not a string', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.iss = 123;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "iis" required (string)');
    });

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

    it('Throws error when claim "sub" missing', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      delete invlidClaims.sub;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "sub" required (string, max 255 ASCII characters)');
    });

    it('Throws error when claim "sub" not a string', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.sub = 12345;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "sub" required (string, max 255 ASCII characters)');
    });

    it('Throws error when claim "sub" exceeds 255 ASCII characters', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.sub = new Array(256 + 1).join('X');

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "sub" required (string, max 255 ASCII characters)');
    });
  });
});

describe(
'OpenID Connect Basic Client Implementer\'s Guide 1.0 - draft 37 ' +
'(https://openid.net/specs/openid-connect-basic-1_0-37.html#IDToken) ' +
'The ID Token is a security token that contains Claims about the authentication of ' +
'an End-User by an Authorization Server when using a Client, and potentially other requested ' +
'Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].', () => {
  context(
  'The following Claims are used within the ID Token:', () => {
    const jwtIdToken = idToken.createJwt(privatePem, {
      iss: 'https://EXAMPLE.com:12345/path',
      sub: 'AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4',
    });
    const idTokenPayload = jwt.verify(jwtIdToken, publicPem, { algorithms: ['RS256'] });

    it(
    'iss: REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a ' +
    'case-sensitive URL using the https scheme that contains scheme, host, and optionally, ' +
    'port number and path components and no query or fragment components.', () => {
      assert.equal(idTokenPayload.iss, 'https://EXAMPLE.com:12345/path');
    });

    it(
    'sub: REQUIRED. Subject Identifier. Locally unique and never reassigned identifier within ' +
    'the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 ' +
    'or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. ' +
    'The sub value is a case-sensitive string.', () => {
      assert.equal(idTokenPayload.sub, 'AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4');
     });
  });
});
