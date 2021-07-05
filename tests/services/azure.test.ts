import axios from 'axios';
import * as jwt from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
import { Jwt, JwtPayload } from '../../src/types/types';
import { Logger } from '../../src/util/logger';
import { Azure } from '../../src/services/azure';

console.info = jest.fn();

let azure: Azure;

const logger: Logger = new Logger('');
const loggerPrefix = 'Failed to verify jwt::';

describe('Test Azure', () => {
  const jwks = createJWKSMock('https://login.microsoftonline.com/tenant_id', '/discovery/keys');

  beforeEach(() => {
    azure = new Azure('tenant_id', 'client_id', logger);
    jwks.start();
  });

  afterEach(async () => {
    await jwks.stop();
  });

  test('getIssuer() should return url with tenant id', () => {
    expect(azure.getIssuer()).toBe('https://login.microsoftonline.com/tenant_id/v2.0');
  });

  test('verify() should return true for correct jwt', async () => {
    const token = jwks.token({
      iss: azure.getIssuer(),
      aud: 'client_id',
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    const token = jwks.token({
      iss: azure.getIssuer(),
      aud: 'client_id',
      exp: 60,
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenCalledWith(
      logger.logFormat,
      `${loggerPrefix} jwt expired`,
    );
  });

  test('verify() should return false for invalid client_id', async () => {
    const token = jwks.token({
      iss: azure.getIssuer(),
      aud: 'wrong_client_id',
    });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenCalledWith(
      logger.logFormat,
      `${loggerPrefix} jwt audience invalid. expected: client_id`,
    );
  });
});
