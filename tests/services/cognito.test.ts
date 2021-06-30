import * as cognito from '../../src/services/cognito';

describe('Test cognito service', () => {

  test('getIssuer throws error when ', () => {

  }
  test('getIssuer returns url with region and poolId', () => {
    const res = cognito.getIssuer();
    expect(res).toMatch('https://cognito-idp.region.amazonaws.com/poolId');
  });
});
