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
      aud: 'xyZ123',
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
      assert.equal(idTokenPayload.iss, 'http://example.com');
      assert.equal(idTokenPayload.sub, 'Abc123');
      assert.equal(idTokenPayload.aud, 'xyZ123');
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

    it('Throws error when required claim "iss" missing', () => {
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

    it('Throws error when claim "iss" is empty', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.iss = '';

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

    it('Throws error when required claim "sub" missing', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      delete invlidClaims.sub;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "sub" required (string, max 255 ASCII characters)');
    });

    it('Throws error when required claim "sub" empty', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.sub = '';

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

    it('Throws error when required claim "aud" missing', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.aud = '';

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "aud" required (string OR array of strings)');
    });

    it('Throws error when claim "aud" not a string', () => {
      const invlidClaims = Object.assign({}, defaultClaims);
      invlidClaims.aud = 12345;

      assert.throw(() => idToken.createJwt(privatePem, invlidClaims),
        'claim "aud" required (string OR array of strings)');
    });

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
  });
});

// Implementing https://openid.net/specs/openid-connect-basic-1_0-37.html#IDToken
describe(
'OpenID Connect Basic Client Implementer\'s Guide 1.0 - draft 37 ' +
'(https://openid.net/specs/openid-connect-basic-1_0-37.html#IDToken) ' +
'The ID Token is a security token that contains Claims about the authentication of ' +
'an End-User by an Authorization Server when using a Client, and potentially other requested ' +
'Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].', () => {
  context(
  'The following Claims are used within the ID Token:', () => {
    const jwtIdToken = idToken.createJwt(privatePem, {
      iss: 'https://server.example.com',
      sub: '24400320',
      aud: 's6BhdRkqt3',
    });
    const idTokenPayload = jwt.verify(jwtIdToken, publicPem, { algorithms: ['RS256'] });

    it(
    'iss: REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a ' +
    'case-sensitive URL using the https scheme that contains scheme, host, and optionally, ' +
    'port number and path components and no query or fragment components.', () => {
      assert.equal(idTokenPayload.iss, 'https://server.example.com');
    });

    it(
    'sub: REQUIRED. Subject Identifier. Locally unique and never reassigned identifier within ' +
    'the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 ' +
    'or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. ' +
    'The sub value is a case-sensitive string.', () => {
      assert.equal(idTokenPayload.sub, '24400320');
    });

    it(
    'aud: REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 ' +
    'client_id of the Relying Party as an audience value. It MAY also contain identifiers for other ' +
    'audiences. In the general case, the aud value is an array of case-sensitive strings. In the common ' +
    'special case when there is one audience, the aud value MAY be a single case-sensitive string.', () => {
      assert.equal(idTokenPayload.aud, 's6BhdRkqt3');
    });

    it.skip(
    'exp: REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. ' +
    'The processing of this parameter requires that the current date/time MUST be before the ' +
    'expiration date/time listed in the value. Implementers MAY provide for some small leeway, ' +
    'usually no more than a few minutes, to account for clock skew. Its value is a JSON [RFC7159] ' +
    'number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the ' +
    'date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.', () => {
      assert.fail();
    });

    it.skip(
    'iat: REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number ' +
    'of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.', () => {
      assert.fail();
    });

    it.skip(
    'auth_time: Time when the End-User authentication occurred. Its value is a JSON number representing ' +
    'the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. When a ' +
    'max_age request is made then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.', () => {
      assert.fail();
    });

    it.skip(
    'nonce: OPTIONAL. String value used to associate a Client session with an ID Token, and to ' +
    'mitigate replay attacks. The value is passed through unmodified from the Authentication Request ' +
    'to the ID Token. The Client MUST verify that the nonce Claim Value is equal to the value of the ' +
    'nonce parameter sent in the Authentication Request. If present in the Authentication Request, ' +
    'Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being ' +
    'the nonce value sent in the Authentication Request. The nonce value is a case-sensitive string.', () => {
      assert.fail();
    });

    it.skip(
    'at_hash: OPTIONAL. Access Token hash value. This is OPTIONAL when the ID Token is issued ' +
    'from the Token Endpoint, which is the case for this subset of OpenID Connect; nonetheless, ' +
    'an at_hash Claim MAY be present. Its value is the base64url encoding of the left-most half of ' +
    'the hash of the octets of the ASCII representation of the access_token value, where the hash ' +
    'algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token\'s ' +
    'JOSE Header. For instance, if the alg is RS256, hash the access_token value with SHA-256, ' +
    'then take the left-most 128 bits and base64url-encode them. The at_hash value is a case-sensitive ' +
    'string.', () => {
      assert.fail();
    });

    it.skip(
    'acr: OPTIONAL. Authentication Context Class Reference. String specifying an Authentication ' +
    'Context Class Reference value that identifies the Authentication Context Class that the ' +
    'authentication performed satisfied. The value "0" indicates the End-User authentication did ' +
    'not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived ' +
    'browser cookie, for instance, is one example where the use of "level 0" is appropriate. ' +
    'Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary ' +
    'value. An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; ' +
    'registered names MUST NOT be used with a different meaning than that which is registered. Parties ' +
    'using this claim will need to agree upon the meanings of the values used, which may be context ' +
    'specific. The acr value is a case-sensitive string.', () => {
      assert.fail();
    });

    it.skip(
    'amr: OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers ' +
    'for authentication methods used in the authentication. For instance, values might indicate that ' +
    'both password and OTP authentication methods were used. The definition of particular values to ' +
    'be used in the amr Claim is beyond the scope of this document. Parties using this claim will need ' +
    'to agree upon the meanings of the values used, which may be context specific. The amr value is an ' +
    'array of case-sensitive strings.', () => {
      assert.fail();
    });

    it.skip(
    'azp: OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, ' +
    'it MUST contain the OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token ' +
    'has a single audience value and that audience is different than the authorized party. It MAY be ' +
    'included even when the authorized party is the same as the sole audience. The azp value is a ' +
    'case-sensitive string containing a StringOrURI value.', () => {
      assert.fail();
    });

    it.skip(
    'ID Tokens MAY contain other Claims. Any Claims used that are not understood MUST be ignored.', () => {
      assert.fail();
    });

    it.skip(
    'ID Tokens SHOULD NOT use the JWS or JWE x5u, x5c, jku, or jwk Header Parameter fields. ' +
    'Instead, keys used for ID Tokens are communicated in advance using Discovery and Registration ' +
    'parameters.', () => {
      assert.fail();
    });
  });
});
