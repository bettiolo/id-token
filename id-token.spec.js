import path from 'path';
import fs from 'fs';
import { assert } from 'chai';
import jwt from 'jsonwebtoken';
import idToken from './index';
import getPem from 'rsa-pem-from-mod-exp';
import publicJwk from './src/test-data/test1-jwk.json';

const privatePemPath = path.join(__dirname, `./src/test-data/test1-private.pem`);
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
      auth_time: nowEpoch,
      nonce: 'vr2MrVSjyfu0UbrOtjWG',
    }, {
      accessToken: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      authorizationCode: 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk',
      kid: '1e9gdk7',
    });
    const idTokenPayload = jwt.verify(jwtIdToken, publicPem, { algorithms: ['RS256'] });
    const idTokenHeader = jwt.decode(jwtIdToken, { complete: true }).header;

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

    it(
    'auth_time: Time when the End-User authentication occurred. Its value is a JSON number representing ' +
    'the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. [...] ' +
    'its inclusion is OPTIONAL.', () => {
      assert.equal(idTokenPayload.auth_time, nowEpoch);
    });

    it(
    'nonce: OPTIONAL. String value used to associate a Client session with an ID Token, and to ' +
    'mitigate replay attacks. The value is passed through unmodified from the Authentication Request ' +
    'to the ID Token. [...] If present in the Authentication Request, Authorization Servers MUST ' +
    'include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the ' +
    'Authentication Request. The nonce value is a case-sensitive string.', () => {
      assert.equal(idTokenPayload.nonce, 'vr2MrVSjyfu0UbrOtjWG');
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

    // Optional claim: http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
    it(
    'at_hash: Access Token hash value. Its value is the base64url encoding of the left-most half of ' +
    'the hash of the octets of the ASCII representation of the access_token value, where the hash ' +
    'algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token\'s JOSE ' +
    'Header. For instance, if the alg is RS256, hash the access_token value with SHA-256, then take ' +
    'the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string. ' +
    'If the ID Token is issued from the Authorization Endpoint with an access_token value, which is ' +
    'the case for the response_type value code id_token token, this is REQUIRED; otherwise, its ' +
    'inclusion is OPTIONAL.', () => {
      assert.equal(idTokenPayload.at_hash, '77QmUPtjPfzWtF2AnpK9RQ');
    });

    // Optional claim: http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
    it(
    'c_hash: Code hash value. Its value is the base64url encoding of the left-most half of the hash ' +
    'of the octets of the ASCII representation of the code value, where the hash algorithm used is ' +
    'the hash algorithm used in the alg Header Parameter of the ID Token\'s JOSE Header. For instance, ' +
    'if the alg is HS512, hash the code value with SHA-512, then take the left-most 256 bits and ' +
    'base64url encode them. The c_hash value is a case sensitive string. If the ID Token is issued ' +
    'from the Authorization Endpoint with a code, which is the case for the response_type values ' +
    'code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is ' +
    'OPTIONAL.', () => {
      assert.equal(idTokenPayload.c_hash, 'LDktKdoQak3Pk0cnXxCltA');
    });

    // Optional header parameter: https://tools.ietf.org/html/rfc7515#section-4.1.4
    it(
    'kid: (Key ID) Header Parameter. The "kid" (key ID) Header Parameter is a hint indicating which ' +
    'key was used to secure the JWS.  This parameter allows originators to explicitly signal a ' +
    'change of key to recipients.  The structure of the "kid" value is unspecified.  Its value ' +
    'MUST be a case-sensitive string.  Use of this Header Parameter is OPTIONAL. When used with a JWK, ' +
    'the "kid" value is used to match a JWK "kid" parameter value.', () => {
      assert.equal(idTokenHeader.kid, '1e9gdk7');
    });
  });

  // Taken from "OpenID Connect Core 1.0 - draft 23 incorporating errata set 2"
  // http://openid.bitbucket.org/openid-connect-core-1_0.html#code-id_token-tokenExample
  // The Section A.6 has a bug in "OpenID Connect Core 1.0 incorporating errata set 1"
  context(
  'A.6.  Example using response_type=code id_token token', () => {
    it('Generated ID Token matches the expected one', () => {
      const jwtIdToken = idToken.createJwt(privatePem, {
        iss: 'https://server.example.com',
        sub: '248289761001',
        aud: 's6BhdRkqt3',
        nonce: 'n-0S6_WzA2Mj',
        exp: 1311281970,
        iat: 1311280970,
      }, {
        accessToken: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        authorizationCode: 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk',
        kid: '1e9gdk7',
      });

      const idTokenPayload = jwt.verify(jwtIdToken, publicPem, {
        algorithms: ['RS256'],
        ignoreExpiration: true,
      });
      const idTokenHeader = jwt.decode(jwtIdToken, { complete: true }).header;

      assert.equal(idTokenHeader.alg, 'RS256');
      assert.equal(idTokenHeader.kid, '1e9gdk7');

      assert.deepEqual(idTokenPayload, {
        'iss': 'https://server.example.com',
        'sub': '248289761001',
        'aud': 's6BhdRkqt3',
        'nonce': 'n-0S6_WzA2Mj',
        'exp': 1311281970,
        'iat': 1311280970,
        'at_hash': '77QmUPtjPfzWtF2AnpK9RQ',
        'c_hash': 'LDktKdoQak3Pk0cnXxCltA',
      });
    });
  });
});

// TODO: Update the spec to use the wording of http://openid.net/specs/openid-connect-core-1_0.html
// TODO: Test spec Examples: http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.A
