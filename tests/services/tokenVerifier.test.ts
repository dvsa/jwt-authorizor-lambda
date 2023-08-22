/* eslint-disable @typescript-eslint/dot-notation */
import { sign } from 'jsonwebtoken';
import createJWKSMock from 'mock-jwks';
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
    jwks.stop();

    expect(cognitoSpy).toHaveBeenCalled();
    expect(azureSpy).not.toHaveBeenCalled();
    expect(res).toBe(true);
  });

  test('verify() to call azure.verify for a cognito JWT', async () => {
    const jwks = createJWKSMock('https://sts.windows.net/tenant_id', '/discovery/keys');
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
    jwks.stop();
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

  test('verify() logs and returns false when decoding jwt errors', async () => {
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');

    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);
    const azure = new Azure('tenant_id', 'client_id', logger);
    const tokenVerifier = new TokenVerifier(cognito, azure, logger);

    const res = await tokenVerifier.verify('token');

    expect(loggerSpy).toHaveBeenCalledWith('Failed to decode provided JWT');
    expect(res).toBe(false);
  });

  test('getVerifiedDecodedToken() to call cognito.verify for a cognito JWT and return the decoded token', async () => {
    const jwks = createJWKSMock('https://cognito-idp.region.amazonaws.com/pool_id');
    jwks.start();

    const cognito = new Cognito('region', 'pool_id', ['client_id'], new Logger(''));
    const cognitoSpy = jest.spyOn(cognito, 'verify');

    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    const azureSpy = jest.spyOn(azure, 'verify');

    const token = jwks.token({ iss: cognito.getIssuer(), token_use: 'access', client_id: 'client_id' });

    const tokenVerifier = new TokenVerifier(cognito, azure, new Logger(''));
    const res = await tokenVerifier.getVerifiedDecodedToken(token);
    jwks.stop();

    expect(cognitoSpy).toHaveBeenCalled();
    expect(azureSpy).not.toHaveBeenCalled();
    expect(res.header.typ).toBe('JWT');
    expect(res.payload['iss']).toBe('https://cognito-idp.region.amazonaws.com/pool_id');
  });

  test('getVerifiedDecodedToken() to call azure.verify for a cognito JWT and return the decoded token', async () => {
    const jwks = createJWKSMock('https://sts.windows.net/tenant_id', '/discovery/keys');
    jwks.start();

    const cognito = new Cognito('region', 'pool_id', ['client_id'], new Logger(''));
    const cognitoSpy = jest.spyOn(cognito, 'verify');

    const azure = new Azure('tenant_id', 'client_id', new Logger(''));
    const azureSpy = jest.spyOn(azure, 'verify');

    const token = jwks.token({ iss: azure.getIssuer(), aud: 'client_id' });

    const tokenVerifier = new TokenVerifier(cognito, azure, new Logger(''));
    const res = await tokenVerifier.getVerifiedDecodedToken(token);

    expect(azureSpy).toHaveBeenCalled();
    expect(cognitoSpy).not.toHaveBeenCalled();
    expect(res.header.typ).toBe('JWT');
    expect(res.payload['iss']).toBe('https://sts.windows.net/tenant_id/');
    jwks.stop();
  });

  test('getVerifiedDecodedToken() returns undefined when issuer is not accepted', async () => {
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');

    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);
    const cognitoSpy = jest.spyOn(cognito, 'verify');

    const azure = new Azure('tenant_id', 'client_id', logger);
    const azureSpy = jest.spyOn(azure, 'verify');

    const tokenVerifier = new TokenVerifier(cognito, azure, logger);
    const res = await tokenVerifier.getVerifiedDecodedToken(sign({ iss: 'incorrect' }, 'secret'));

    expect(azureSpy).not.toHaveBeenCalled();
    expect(cognitoSpy).not.toHaveBeenCalled();
    expect(loggerSpy).toHaveBeenCalledWith("Token issuer 'incorrect' not accepted");
    expect(res).toBeUndefined();
  });

  test('getVerifiedDecodedToken() logs and returns undefined when decoding jwt errors', async () => {
    const logger = new Logger('');
    const loggerSpy = jest.spyOn(logger, 'info');

    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);
    const azure = new Azure('tenant_id', 'client_id', logger);
    const tokenVerifier = new TokenVerifier(cognito, azure, logger);

    const res = await tokenVerifier.getVerifiedDecodedToken('token');

    expect(loggerSpy).toHaveBeenCalledWith('Failed to decode provided JWT');
    expect(res).toBeUndefined();
  });
});
