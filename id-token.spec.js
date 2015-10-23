import path from 'path';
import fs from 'fs';
import { assert } from 'chai';
import jwt from 'jsonwebtoken';
import idToken from './id-token';
import getPem from 'rsa-pem-from-mod-exp';
import publicJwk from '../../test/data/test1-jwk.json';

const privatePemPath = path.join(__dirname, `../../test/data/test1-private.pem`);
const privatePem = fs.readFileSync(privatePemPath, 'ascii');
const publicPem = getPem(publicJwk.n, publicJwk.e);

// Implementing https://openid.net/specs/openid-connect-basic-1_0-37.html#IDToken
describe(
  'OpenID Connect Basic Client Implementer\'s Guide 1.0 - draft 37 ' +
  '(https://openid.net/specs/openid-connect-basic-1_0-37.html#IDToken) ' +
  'The ID Token is a security token that contains Claims about the authentication of ' +
  'an End-User by an Authorization Server when using a Client, and potentially other requested ' +
  'Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].', () => {
    context(
      'The following Claims are used within the ID Token:', () => {
        const nowEpoch = Math.floor(Date.now() / 1000);
        const absoluteExpiryIn1Minute = nowEpoch + 60;
        const jwtIdToken = idToken.createJwt(privatePem, {
          iss: 'https://server.example.com',
          sub: '24400320',
          aud: 's6BhdRkqt3',
          exp: absoluteExpiryIn1Minute,
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

        it(
          'exp: REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. ' +
          '[...] Its value is a JSON [RFC7159] number representing the number of seconds from ' +
          '1970-01-01T00:00:00Z as measured in UTC until the date/time. [...]', () => {
            assert.ok(idTokenPayload.exp > nowEpoch);
            assert.ok(idTokenPayload.exp > idTokenPayload.iat);
          });

        it(
          'iat: REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number ' +
          'of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.', () => {
            assert.ok(idTokenPayload.iat >= nowEpoch);
          });

        it.skip(
          'auth_time: Time when the End-User authentication occurred. Its value is a JSON number representing ' +
          'the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. [...] ' +
          'its inclusion is OPTIONAL.', () => {
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
