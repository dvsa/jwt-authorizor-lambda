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
});
