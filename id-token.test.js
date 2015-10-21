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
    it('Creates a JWT Token', () => {
      const jwtIdToken = idToken.createJwt(privatePem);

      assert.isString(jwtIdToken);
    });

    it('Signs the token using RS256 algorithm', () => {
      const jwtIdToken = idToken.createJwt(privatePem);
      const decodedIdToken = jwt.decode(jwtIdToken, { complete: true });

      assert.equal(decodedIdToken.header.alg, 'RS256');
    });

    it('Creates a signed JWT ID Token', () => {
      const jwtIdToken = idToken.createJwt(privatePem);
      const idTokenPayload = jwt.verify(jwtIdToken, publicPem, { algorithms: ['RS256'] });

      assert.isObject(idTokenPayload);
    });

    it('Does not validate JWT ID Token with wrong Public RSA Key', (done) => {
      const jwtIdToken = idToken.createJwt(privatePem);
      jwt.verify(jwtIdToken, wrongPublicPem, { algorithms: ['RS256'] }, (err, idTokenPayload) => {
        assert.isUndefined(idTokenPayload);
        assert.equal(err.message, 'invalid signature');
        done();
      });
    });
  });
});

describe.skip('The ID Token is a security token that contains Claims about the authentication of ' +
         'an End-User by an Authorization Server when using a Client, and potentially other requested ' +
         'Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].', () => {
  context('The following Claims are used within the ID Token:', () => {
    it('iss: REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a ' +
       'case-sensitive URL using the https scheme that contains scheme, host, and optionally, ' +
       'port number and path components and no query or fragment components.', (done) => {
      assert.fail();
      done();
    })
  });
});
