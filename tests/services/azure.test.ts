import axios from 'axios';
import * as jwt from 'jsonwebtoken';
import { loadConfig, AuthorizerConfig } from '../../src/services/configuration';
import { Jwt, JwtPayload } from '../../src/types/types';
import { createLogger, Logger } from '../../src/util/logger';
import { Azure } from '../../src/services/azure';

jest.mock('axios');
console.info = jest.fn();

let config: AuthorizerConfig;
let azure: Azure;

const mockedAxios = axios as jest.Mocked<typeof axios>;
const logger: Logger = new Logger('');
const loggerPrefix = 'Failed to verify jwt::';

const privateKey: string = '-----BEGIN PRIVATE KEY-----\n'
  + 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCMoAAhrNv6CnOr\n'
  + 'RFQp7gIytohWYEpzSD78fmu2DdrimoNAo1iQ1teWjGh/6Px4iUef7Vw7tFrYneDp\n'
  + 'ZTHgOiLDTlK+wlAZSJhDgjhHUVidAtDQ6iFBH9yPHyjn8dhPiss6pbq/7jSKnrTy\n'
  + 'iq6AP7IHPG9s288eWT9z8shLo8hqXbWR/Y86cmwgQSRVY9ptUo29i+nlheOlS824\n'
  + 'oLL1znfWRIuTkAA8NLZqZXuJFktLP9KJE03yiRaUi/6IJ5S7Mg/YzYSGdWZ9qWyv\n'
  + 'yGVObRC4GkwNgTJBRs3hEQG5PsNfso+gVC7VeUd4JyD7JWaJpg6YO8OObrQSqLVE\n'
  + 'wqWNS9JRAgMBAAECggEAYGFE1c+4kL3bGxXgrUAwB3vtI24peKuaZ8lpn0QNseN+\n'
  + 'c63AhLyK0+b1tD0F1MMZ8PVoko8A+Jf0T2KI9YpCyyMCOTXKWhnUKei1E8Qf/LSy\n'
  + 'U400L4Nb0kfj7FxoCdQxh8eQn/zty9gMYnNEOCfvp1/3al+Yq881Ww2Z06W0NZlw\n'
  + 'Ph1xhnrC6tDAmGhwX12Wsy1mGZnvC+HPwonwcHvFKnx2cFT/irorb02kWkbeP1rx\n'
  + '5BOfoAIarDn4H/rH1tngC+m2+8HC/cWCSbczUk8SuydbQNz+gmsz0FCJFBDjHV42\n'
  + 'XqUMvtXwHBLRaPT/7M7X0gvo8WN1dxsHzxPogLg69QKBgQDW7PD+FhlapszNEYv+\n'
  + 'iWrmeF3+tozHhb3ebhq00ZtMIibcRu/sqIEsebo9AieTZJ9u249I6pRb0zcEgf3/\n'
  + 'ibeHn4UvLZLTssyqZmZoTPMwCdNYc6PDm89cbvA8i/0ByLndNG5OpDQtYHe3mrK5\n'
  + '/hQwiz+gAcHErZjtCjK1Co+9/wKBgQCnf/cCF9j15zQ52XgpW416I1R/ENt1N6QS\n'
  + 'wDNeX5YhpIZGX+AZO3nqveMGuBDWcspxn8WB6apKnKWdkB9nmaR8anJrGWDJv6vr\n'
  + 'oPrSv1xcOD33jKnrPRVsa/Qc+P5ZLlKp2yjF6cXSvdzw/srFM6+0s8MoBCH3rDui\n'
  + 'Qjw6pRkPrwKBgQCC9Vsep16JkwtFhQSVcywVBJDZjGgZhw+bQeG5/eIvsLuXCw5U\n'
  + 'WJRlAkMNu4tbzzsqdFRJbM47aWajs4WOOF8BH50qkw1dOxxkVALgWMrxoXsK8WN+\n'
  + '5CikvOBbND1U4fcGp1TzTDCS2a34zSVMGVo5/g8lswxbiB+fh9A/6hCOBwKBgQCR\n'
  + 'pdEIjeoHsVqVbwdwlv6HlQ8VSng6Df7qmxxP1Lg8Ws6zhQzdg/04ZJNztTxW7Qwi\n'
  + 'Dzb0B1YfeOT+BGN6d3wy/3Csti2WYMfCpYFVHjbWrcUca8EZH01wsNJdGxo4O/J/\n'
  + 'ZmWm6ucsoBHtsPBq183SSHnLYwSSU76rEgNDT2piWwKBgF66t6drIbnbWf4i9yi6\n'
  + 'DCNL4TaPnLwEgxFnqQ9plSGxcHPJeF0oWZE/H2QEeJIhSry5pSwrKRS3EfUvlvz2\n'
  + 'T73uF/zqlwEgF3xNGmPHJWIN3fG1vQqAXrtWzYhuUeNBGj3OIYyBlLRKIdGxu5Hl\n'
  + '3NjkeGN6IDxt6k5+9LfBTxdQ\n'
  + '-----END PRIVATE KEY-----';

const response = {
  keys: [
    {
      kty: 'RSA',
      use: 'sig',
      kid: '1234example=',
      x5t: '1234example=',
      // eslint-disable-next-line max-len
      n: 'jKAAIazb-gpzq0RUKe4CMraIVmBKc0g-_H5rtg3a4pqDQKNYkNbXloxof-j8eIlHn-1cO7Ra2J3g6WUx4Doiw05SvsJQGUiYQ4I4R1FYnQLQ0OohQR_cjx8o5_HYT4rLOqW6v-40ip608oqugD-yBzxvbNvPHlk_c_LIS6PIal21kf2POnJsIEEkVWPabVKNvYvp5YXjpUvNuKCy9c531kSLk5AAPDS2amV7iRZLSz_SiRNN8okWlIv-iCeUuzIP2M2EhnVmfalsr8hlTm0QuBpMDYEyQUbN4REBuT7DX7KPoFQu1XlHeCcg-yVmiaYOmDvDjm60Eqi1RMKljUvSUQ',
      x5c: [
        // eslint-disable-next-line max-len
        'MIIC6jCCAdKgAwIBAgIGAXpdd59IMA0GCSqGSIb3DQEBCwUAMDYxNDAyBgNVBAMMKzJ1MmNNSG5vWWR3eWxXYWxVN0tvRFd2YnRERm90VkVPSzBXd1JJMDBBMWcwHhcNMjEwNjMwMTUwOTE4WhcNMjIwNDI2MTUwOTE4WjA2MTQwMgYDVQQDDCsydTJjTUhub1lkd3lsV2FsVTdLb0RXdmJ0REZvdFZFT0swV3dSSTAwQTFnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjKAAIazb+gpzq0RUKe4CMraIVmBKc0g+/H5rtg3a4pqDQKNYkNbXloxof+j8eIlHn+1cO7Ra2J3g6WUx4Doiw05SvsJQGUiYQ4I4R1FYnQLQ0OohQR/cjx8o5/HYT4rLOqW6v+40ip608oqugD+yBzxvbNvPHlk/c/LIS6PIal21kf2POnJsIEEkVWPabVKNvYvp5YXjpUvNuKCy9c531kSLk5AAPDS2amV7iRZLSz/SiRNN8okWlIv+iCeUuzIP2M2EhnVmfalsr8hlTm0QuBpMDYEyQUbN4REBuT7DX7KPoFQu1XlHeCcg+yVmiaYOmDvDjm60Eqi1RMKljUvSUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAAJXeexo6qUNtPWaHv62n8p/eOu/n1Vx5w3+D9H+r8kj4P3FER6PENPz36PmdieIWtKo7b400UoTWSZLNgtjWdAzBtOcXshdB4MolRxM8dAWSYYyvG3KqaBAtEmna7deoSTJox/JV4onYjrzkb73SJzCDz7cCB0+cpZYcXYbl6CLatC7/epQufAEQ6uj7AJP29zy1+xJtKYFiQJdiC3NR2oCudk5imitcy6rDBZjjcj/ux4k/QKljn43jUN6PelrkvN7ShiXRGiHjbCd28M78J1qvz3YtJ2OAaE4kedYhEpTwgqsfkjoxOylbuSH1XCodoVySz7Oq0Xwytrc7pLRYU',
      ],
    },
  ],
};

describe('Test Azure', () => {
  jest.mock('axios');
  beforeEach(() => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.COGNITO_CLIENT_ID = 'cognito_client_id';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    config = loadConfig();
    azure = new Azure(config.azure.tenantId, config.azure.clientId, logger);
  });

  test('getIssuer() should return url with tenant id', () => {
    expect(azure.getIssuer()).toBe('https://login.microsoftonline.com/azure_tenant_id/v2.0');
  });

  test('verify() should return true for correct jwt', async () => {
    const payload: JwtPayload = {
      iss: azure.getIssuer(),
      client_id: config.cognito.clientId,
      aud: config.azure.clientId,
    };
    const token = jwt.sign(payload, privateKey, { expiresIn: '1h', keyid: '1234example=', algorithm: 'RS256' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await azure.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    const payload: JwtPayload = {
      iss: azure.getIssuer(),
      client_id: config.cognito.clientId,
      aud: config.azure.clientId,
    };
    const token = jwt.sign(payload, privateKey, { expiresIn: -60, keyid: '1234example=', algorithm: 'RS256' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenCalledWith(
      logger.logFormat,
      `${loggerPrefix} jwt expired`,
    );
  });

  test('verify() should return false for invalid client_id', async () => {
    const payload: JwtPayload = {
      iss: azure.getIssuer(),
      client_id: config.cognito.clientId,
      aud: 'config.azure.clientId',
    };
    const token = jwt.sign(payload, privateKey, { expiresIn: '1h', keyid: '1234example=', algorithm: 'RS256' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenCalledWith(
      logger.logFormat,
      `${loggerPrefix} jwt audience invalid. expected: azure_client_id`,
    );
  });

  test('verify() should return false for invalid key', async () => {
    const payload: JwtPayload = {
      iss: azure.getIssuer(),
      client_id: config.cognito.clientId,
      aud: config.azure.clientId,
    };
    const token = jwt.sign(payload, privateKey, { expiresIn: '1h', keyid: 'keyid', algorithm: 'RS256' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await azure.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenCalledWith(
      logger.logFormat,
      `${loggerPrefix} no public key with ID 'keyid' under tenant azure_tenant_id`,
    );
  });
});
