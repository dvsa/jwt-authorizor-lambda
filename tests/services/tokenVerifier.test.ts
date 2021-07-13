import { sign } from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
import { mocked } from 'ts-jest/utils';
import { TokenVerifier } from '../../src/services/tokenVerifier';
import { Cognito } from '../../src/services/cognito';
import { Azure } from '../../src/services/azure';
import { Logger } from '../../src/util/logger';

jest.mock('../../src/util/logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  })),
}));

describe('Test tokenVerifier', () => {
  const MockedLogger = mocked(Logger, true);

  beforeEach(() => {
    MockedLogger.mockClear();
  });

  test('decode() throws error when fails to decode jwt', () => {
    // Setup sut
    const cognito = new Cognito('region', 'pool_id', ['client_id'], new Logger(''));
    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    const tokenVerifier = new TokenVerifier(cognito, azure, new Logger(''));

    expect(() => tokenVerifier.decode('token')).toThrow('Failed to decode provided JWT');
  });

  test('verify() to call cognito.verify for a cognito JWT', async () => {
    const jwks = createJWKSMock('https://cognito-idp.region.amazonaws.com/pool_id');
    jwks.start();

    const cognito = new Cognito('region', 'pool_id', ['client_id'], new Logger(''));
    const cognitoSpy = jest.spyOn(cognito, 'verify');

    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    const azureSpy = jest.spyOn(azure, 'verify');

    const token = jwks.token({ iss: cognito.getIssuer(), token_use: 'access', client_id: 'client_id' });

    const tokenVerifier = new TokenVerifier(cognito, azure, new Logger(''));
    const res = await tokenVerifier.verify(token);
    await jwks.stop();

    expect(cognitoSpy).toHaveBeenCalled();
    expect(azureSpy).not.toHaveBeenCalled();
    expect(res).toBe(true);
  });

  test('verify() to call azure.verify for a cognito JWT', async () => {
    const jwks = createJWKSMock('https://login.microsoftonline.com/tenant_id', '/discovery/keys');
    jwks.start();

    const cognito = new Cognito('region', 'pool_id', ['client_id'], new Logger(''));
    const cognitoSpy = jest.spyOn(cognito, 'verify');

    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    const azureSpy = jest.spyOn(azure, 'verify');

    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id' });

    const tokenVerifier = new TokenVerifier(cognito, azure, new Logger(''));
    const res = await tokenVerifier.verify(token);

    expect(azureSpy).toHaveBeenCalled();
    expect(cognitoSpy).not.toHaveBeenCalled();
    expect(res).toBe(true);
  });

  test('verify() returns false when issuer is not accepted', async () => {
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');

    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);
    const cognitoSpy = jest.spyOn(cognito, 'verify');

    const azure = new Azure('tenant_id', 'client_id', logger);
    const azureSpy = jest.spyOn(azure, 'verify');

    const tokenVerifier = new TokenVerifier(cognito, azure, logger);
    const res = await tokenVerifier.verify(sign({ iss: 'incorrect' }, 'secret'));

    expect(azureSpy).not.toHaveBeenCalled();
    expect(cognitoSpy).not.toHaveBeenCalled();
    expect(loggerSpy).toHaveBeenCalledWith("Token issuer 'incorrect' not accepted");
    expect(res).toBe(false);
  });
});
