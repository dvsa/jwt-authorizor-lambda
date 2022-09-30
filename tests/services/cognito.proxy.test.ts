import JwksClient from 'jwks-rsa';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { Cognito } from '../../src/services/cognito';
import { Logger } from '../../src/util/logger';

jest.mock('../../src/util/logger');
jest.mock('jwks-rsa', () => ({
  __esModule: true,
  default: jest.fn().mockReturnValue(({
    getSigningKey: jest.fn().mockReturnValue({ getPublicKey: () => jest.fn() }),
  }),
)}));

describe('Cognito service with proxy settings', () => {
  const oldEnvCache = process.env;

  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    // Reset the env variables.
    process.env = { ...oldEnvCache };
  });

  afterAll(() => {
    process.env = oldEnvCache; // Restore old environment
  });

  test('getPublicKey() should apply proxy if `HTTP_PROXY` environment variable set', async () => {
    const logger = new Logger('');
    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);

    process.env.HTTP_PROXY = 'http://example.com';

    await cognito.getPublicKey('KEY_ID');

    // Define expectations
    expect(JwksClient).toBeCalledWith(expect.objectContaining({ requestAgent: expect.any(HttpsProxyAgent) as unknown }));
  });

  test('getPublicKey() should apply not proxy if `HTTP_PROXY` environment variable set', async () => {
    const logger = new Logger('');
    const cognito = new Cognito('region', 'pool_id', ['client_id'], logger);

    await cognito.getPublicKey('KEY_ID');

    // Define expectations
    expect(JwksClient).toBeCalledWith(expect.objectContaining({ requestAgent: undefined }));
  });
});
