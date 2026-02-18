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
  const jwks = createJWKSMock('https://sts.windows.net/tenant_id', '/discovery/keys');

  beforeEach(() => {
    jwks.start();
  });

  afterEach(() => {
    jwks.stop();
  });

  test('getIssuer() should return url with tenant id', () => {
    // Setup sut
    const azure = new Azure('tenant_id', ['client_id'], new Logger(''));

    // Expectations
    expect(azure.getIssuer()).toBe('https://sts.windows.net/tenant_id/');
  });

  test('verify() should return true for correct jwt', async () => {
    // Setup sut
    const azure = new Azure('tenant_id', ['client_id'], new Logger(''));

    // Setup token
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id' });
    const decodedToken = decode(token, { complete: true });

    // Define expectations
    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    // Setup sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const azure = new Azure('tenant_id', ['client_id'], logger);

    // Setup token
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id', exp: 60 });
    const decodedToken = decode(token, { complete: true });

    // Define expectations
    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt expired');
  });

  test('verify() should return false for invalid client_id', async () => {
    // Setp sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const azure = new Azure('tenant_id', ['client_id'], logger);

    // Setup token
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'wrong_client_id' });
    const decodedToken = decode(token, { complete: true });

    // Define expectations
    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: token contains invalid audience');
  });

  test('verify() should handle if token.aud is an array or string and return true if valid', async () => {
    const logger = new Logger('');
    const azure = new Azure('tenant_id', ['client_id'], logger);

    // token.aud as string
    const tokenWithStringAud = jwks.token({ iss: azure.getIssuer(), aud: 'client_id' });
    const decodedToken = decode(tokenWithStringAud, { complete: true });

    expect(await azure.verify(tokenWithStringAud, decodedToken)).toBe(true);

    // token.aud as array of strings
    const tokenWithArrayAud = jwks.token({ iss: azure.getIssuer(), aud: ['client_id', 'client_id_2'] });
    const decodedToken2 = decode(tokenWithArrayAud, { complete: true });

    expect(await azure.verify(tokenWithArrayAud, decodedToken2)).toBe(true);
  });
});
