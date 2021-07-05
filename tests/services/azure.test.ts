import * as jwt from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
import { mocked } from 'ts-jest/utils';
import { Jwt } from '../../src/types/types';
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
  const jwks = createJWKSMock('https://login.microsoftonline.com/tenant_id', '/discovery/keys');
  const MockedLogger = mocked(Logger, true);

  beforeEach(() => {
    MockedLogger.mockClear();
    jwks.start();
  });

  afterEach(async () => {
    await jwks.stop();
  });

  test('getIssuer() should return url with tenant id', () => {
    // Setup sut
    const azure = new Azure('tenant_id', 'client_id', new Logger(''));

    // Expectations
    expect(azure.getIssuer()).toBe('https://login.microsoftonline.com/tenant_id/v2.0');
  });

  test('verify() should return true for correct jwt', async () => {
    // Setup sut
    const azure = new Azure('tenant_id', 'client_id', new Logger(''));

    // Setup token
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    // Define expectations
    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    // Setup sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const azure = new Azure('tenant_id', 'client_id', logger);

    // Setup token
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id', exp: 60 });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    // Define expectations
    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt expired');
  });

  test('verify() should return false for invalid client_id', async () => {
    // Setp sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const azure = new Azure('tenant_id', 'client_id', logger);

    // Setup token
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'wrong_client_id' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    // Define expectations
    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt audience invalid. expected: client_id');
  });
});
