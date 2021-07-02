import * as jwt from 'jsonwebtoken';
import { mocked } from 'ts-jest/utils';
import { TokenVerifier } from '../../src/services/tokenVerifier';
import { Cognito } from '../../src/services/cognito';
import { Azure } from '../../src/services/azure';
import { Logger } from '../../src/util/logger';

jest.mock('../../src/services/cognito', () => {
  return {
    Cognito: jest.fn().mockImplementation(() => {
      return {
        verify: () => true,
        getIssuer: () => 'https://cognito-idp.region.amazonaws.com/pool_id',
      };
    }),
  };
});
jest.mock('../../src/services/azure', () => {
  return {
    Azure: jest.fn().mockImplementation(() => {
      return {
        verify: () => true,
        getIssuer: () => 'https://cognito-idp.cognito_region.amazonaws.com/cognito_pool_id',
      };
    }),
  };
});
jest.mock('../../src/util/logger', () => {
  return {
    Logger: jest.fn().mockImplementation(() => {
      return {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      };
    }),
  };
});

describe('Test tokenVerifier', () => {
  const MockedCognito = mocked(Cognito, true);
  const MockedAzure = mocked(Azure, true);
  const MockedLogger = mocked(Logger, true);
  beforeEach(() => {
    MockedAzure.mockClear();
    MockedCognito.mockClear();
    MockedLogger.mockClear();
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
    const sut = new TokenVerifier(cognito, azure, logger);

    const res = await sut.verify(jwt.sign({ iss: 'https://cognito-idp.region.amazonaws.com/pool_id' }, 'secret'));
    expect(MockedCognito).toHaveBeenCalled();
    expect(MockedAzure).not.toHaveBeenCalled();
    expect(res).toBe(true);
  });
});
