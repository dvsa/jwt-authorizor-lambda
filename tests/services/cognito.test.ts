import * as jwt from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
import { Cognito } from '../../src/services/cognito';
import { Jwt, JwtPayload } from '../../src/types/types';
import { Logger } from '../../src/util/logger';

console.info = jest.fn();

let cognito: Cognito;

const logger: Logger = new Logger('');
const loggerPrefix = 'Failed to verify jwt::';

describe('Test Cognito', () => {
  const jwks = createJWKSMock('https://cognito-idp.region.amazonaws.com/pool_id');

  beforeEach(() => {
    jwks.start();
    cognito = new Cognito('region', 'pool_id', 'client_id', logger);
  });

  afterEach(async () => {
    await jwks.stop();
  });

  test('getIssuer() should return url with pool id and region', () => {
    expect(cognito.getIssuer()).toBe('https://cognito-idp.region.amazonaws.com/pool_id');
  });

  test('verify() should return true for correct jwt', async () => {
    const token = jwks.token({
      iss: cognito.getIssuer(),
      token_use: 'access',
      client_id: 'client_id',
    });

    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await cognito.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    const token = jwks.token({
      iss: cognito.getIssuer(),
      token_use: 'access',
      client_id: 'client_id',
      exp: 60
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} jwt expired`,
    );
  });

  test('verify() should return false for invalid client_id', async () => {
    const token = jwks.token({
      iss: cognito.getIssuer(),
      token_use: 'access',
      client_id: 'incorrect',
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} contains invalid 'client_id'`,
    );
  });

  test('verify() should return false for invalid token_use', async () => {
    const token = jwks.token({
      iss: cognito.getIssuer(),
      token_use: 'incorrect',
      client_id: 'client_id',
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} contains invalid 'token_use'`,
    );
  });
});
