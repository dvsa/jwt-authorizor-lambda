import { decode } from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';

import { Logger } from '../../src/util/logger';
import { Azure } from '../../src/services/azure';

jest.mock('../../src/util/logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  })),
}));

describe('Test Azure', () => {
  const v1Issuer = 'https://sts.windows.net/tenant_id/';
  const v2Issuer = 'https://login.microsoftonline.com/tenant_id/v2.0';

  const jwksV1 = createJWKSMock('https://sts.windows.net/tenant_id', '/discovery/keys');
  const jwksV2 = createJWKSMock('https://login.microsoftonline.com/tenant_id', '/discovery/v2.0/keys');

  beforeEach(() => {
    jwksV1.start();
    jwksV2.start();
  });

  afterEach(() => {
    jwksV1.stop();
    jwksV2.stop();
  });

  test('getAzureIssuers() should return both v1 and v2 issuer urls', () => {
    const azure = new Azure('tenant_id', ['client_id'], new Logger(''));

    expect(azure.getAzureIssuers()).toEqual([v1Issuer, v2Issuer]);
  });

  test('verify() should return true for correct v1 jwt', async () => {
    const azure = new Azure('tenant_id', ['client_id'], new Logger(''));

    const token = jwksV1.token({ iss: v1Issuer, aud: 'client_id' });
    const decodedToken = decode(token, { complete: true });

    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return true for correct v2 jwt', async () => {
    const azure = new Azure('tenant_id', ['client_id'], new Logger(''));

    const token = jwksV2.token({ iss: v2Issuer, aud: 'client_id' });
    const decodedToken = decode(token, { complete: true });

    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jwt', async () => {
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const azure = new Azure('tenant_id', ['client_id'], logger);

    const token = jwksV1.token({ iss: v1Issuer, aud: 'client_id', exp: 60 });
    const decodedToken = decode(token, { complete: true });

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt expired');
  });

  test('verify() should return false for invalid client_id', async () => {
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const azure = new Azure('tenant_id', ['client_id'], logger);

    const token = jwksV1.token({ iss: v1Issuer, aud: 'wrong_client_id' });
    const decodedToken = decode(token, { complete: true });

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: token contains invalid audience');
  });

  test('verify() should handle if token.aud is an array or string and return true if valid', async () => {
    const logger = new Logger('');
    const azure = new Azure('tenant_id', ['client_id'], logger);

    // token.aud as string
    const tokenWithStringAud = jwksV1.token({ iss: v1Issuer, aud: 'client_id' });
    const decodedToken = decode(tokenWithStringAud, { complete: true });

    expect(await azure.verify(tokenWithStringAud, decodedToken)).toBe(true);

    // token.aud as array of strings
    const tokenWithArrayAud = jwksV1.token({ iss: v1Issuer, aud: ['client_id', 'client_id_2'] });
    const decodedToken2 = decode(tokenWithArrayAud, { complete: true });

    expect(await azure.verify(tokenWithArrayAud, decodedToken2)).toBe(true);
  });
});
