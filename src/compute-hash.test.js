import {assert} from 'chai';
import computeHash from './compute-hash';

it(`Is expected function`, () => {
  assert.isFunction(computeHash);
  assert.equal(computeHash.name, 'computeHash');
});

context(`${computeHash.name}()`, () => {
  it('Computes sha256 access token hash (at_hash) for algorithm RS256', () => {
    // Based on: http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.A.3
    const accessToken = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
    const atHash = computeHash('RS256', accessToken);

    assert.equal(atHash, '77QmUPtjPfzWtF2AnpK9RQ');
  });

  it('Computes sha256 code hash (c_hash) for algorithm RS256', () => {
    // Based on: http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.A.4
    const code = 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk';
    const cHash = computeHash('RS256', code);

    assert.equal(cHash, 'LDktKdoQak3Pk0cnXxCltA');
  });

  it('Throws an error if algorithm unknown', () => {
    const invalidAlgorithm = 'AB123';

    assert.throw(() => computeHash(invalidAlgorithm, 'any-access-token-or-code'),
      'Invalid algorithm');
  });

  it('Throws an error if access token or code missing', () => {
    assert.throw(() => computeHash('HS512'),
      'Argument "accessTokenOrCode" required (string)');
  });

  it('Throws an error if access token or code not a string', () => {
    assert.throw(() => computeHash('HS512', 12345),
      'Argument "accessTokenOrCode" required (string)');
  });
});
