import * as jwt from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
import { mocked } from 'ts-jest/utils';
import { Jwt, JwtPayload } from '../../src/types/types';
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

console.info = jest.fn();

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
    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    expect(azure.getIssuer()).toBe('https://login.microsoftonline.com/tenant_id/v2.0');
  });

  test('verify() should return true for correct jwt', async () => {
    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    const logger = new Logger('');
    const azure = new Azure('tenant_id', 'client_id', logger);
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id', exp: 60 });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    const loggerSpy = jest.spyOn(logger, 'info');

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt expired');
  });

  test('verify() should return false for invalid client_id', async () => {
    const logger = new Logger('');
    const azure = new Azure('tenant_id', 'client_id', logger);
    const token = jwks.token({ iss: azure.getIssuer(), aud: 'wrong_client_id' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    const loggerSpy = jest.spyOn(logger, 'info');

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt audience invalid. expected: client_id');
  });
});
