import * as jwt from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
import { mocked } from 'ts-jest/utils';
import { Cognito } from '../../src/services/cognito';
import { Logger } from '../../src/util/logger';
import { Jwt } from '../../src/types/jwt';

jest.mock('../../src/util/logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  })),
}));

describe('Test Cognito', () => {
  const jwks = createJWKSMock('https://cognito-idp.region.amazonaws.com/pool_id');
  const MockedLogger = mocked(Logger, true);

  beforeEach(() => {
    jwks.start();
    MockedLogger.mockClear();
  });

  afterEach(async () => {
    await jwks.stop();
  });

  test('getIssuer() should return url with pool id and region', () => {
    // Setup sut
    const cognito = new Cognito('region', 'pool_id', ['client_id'], new Logger(''));

    // Define expectations
    expect(cognito.getIssuer()).toBe('https://cognito-idp.region.amazonaws.com/pool_id');
  });

  test('verify() should return true for correct jwt', async () => {
    // Setup sut
    const logger = new Logger('');
    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);

    // Setup token
    const token = jwks.token({ iss: cognito.getIssuer(), token_use: 'access', client_id: 'client_id' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true });

    // Define expectations
    expect(await cognito.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    // Setup sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);

    // Setup token
    const token = jwks.token({
      iss: cognito.getIssuer(), token_use: 'access', client_id: 'client_id', exp: 60,
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true });

    // Define expectations
    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith('Failed to verify jwt:: jwt expired');
  });

  test('verify() should return false for invalid client_id', async () => {
    // Setup sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);

    // Setup token
    const token = jwks.token({ iss: cognito.getIssuer(), token_use: 'access', client_id: 'incorrect' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true });

    // Define expectations
    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith("Failed to verify jwt:: contains invalid 'client_id'");
  });

  test('verify() should return false for invalid token_use', async () => {
    // Setup sut
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');
    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);

    // Setup token
    const token = jwks.token({ iss: cognito.getIssuer(), token_use: 'incorrect', client_id: 'client_id' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true });

    // Define expectations
    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(loggerSpy).toHaveBeenCalledWith("Failed to verify jwt:: contains invalid 'token_use'");
  });
});
