import * as jwt from 'jsonwebtoken';
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
    const logger = new Logger('');
    const cognito = new Cognito('region', 'poolId', 'clientId', logger);
    const azure = new Azure('tenantId', 'clientId', logger);
    const sut = new TokenVerifier(cognito, azure, logger);

    expect(() => sut.decode('token')).toThrow('Failed to decode provided JWT');
  });

  test('verify() to call cognito.verify for a cognito JWT', async () => {
    const logger = new Logger('');
    const cognito = new Cognito('region', 'poolId', 'clientId', logger);
    const azure = new Azure('tenantId', 'clientId', logger);
    const cognitoSpy = jest.spyOn(cognito, 'verify');
    const azureSpy = jest.spyOn(azure, 'verify');
    const sut = new TokenVerifier(cognito, azure, logger);
    const res = await sut.verify(jwt.sign({ iss: cognito.getIssuer() }, 'secret'));
    expect(cognitoSpy).toHaveBeenCalled();
    expect(azureSpy).not.toHaveBeenCalled();
    // note res will be false cos the key is not correct
  });

  test('verify() to call azure.verify for a cognito JWT', async () => {
    const logger = new Logger('');
    const cognito = new Cognito('region', 'poolId', 'clientId', logger);
    const azure = new Azure('tenantId', 'clientId', logger);
    const cognitoSpy = jest.spyOn(cognito, 'verify');
    const azureSpy = jest.spyOn(azure, 'verify');

    const sut = new TokenVerifier(cognito, azure, logger);
    const res = await sut.verify(jwt.sign({ iss: azure.getIssuer() }, 'secret'));

    expect(azureSpy).toHaveBeenCalled();
    expect(cognitoSpy).not.toHaveBeenCalled();
    // note res will be false cos the key is not correct
  });

  test('verify() returns false when issuer is not accepted', async () => {
    const logger = new Logger('');
    const cognito = new Cognito('region', 'poolId', 'clientId', logger);
    const azure = new Azure('tenantId', 'clientId', logger);
    const cognitoSpy = jest.spyOn(cognito, 'verify');
    const azureSpy = jest.spyOn(azure, 'verify');
    const loggerSpy = jest.spyOn(logger, 'info');

    const sut = new TokenVerifier(cognito, azure, logger);
    const res = await sut.verify(jwt.sign({ iss: 'incorrect' }, 'secret'));

    expect(azureSpy).not.toHaveBeenCalled();
    expect(cognitoSpy).not.toHaveBeenCalled();
    expect(loggerSpy).toHaveBeenCalledWith("Token issuer 'incorrect' not accepted");
    expect(res).toBe(false);
  });
});
