import axios from 'axios';
import * as jwt from 'jsonwebtoken';
import { loadConfig, AuthorizerConfig } from '../../src/util/configuration';
import { Cognito, PublicKeys } from '../../src/services/cognito';
import { Jwt, JwtPayload } from '../../src/types/types';
import { Logger } from '../../src/util/logger';

jest.mock('axios');
console.info = jest.fn();

let config: AuthorizerConfig;
let cognito: Cognito;

const mockedAxios = axios as jest.Mocked<typeof axios>;
const logger: Logger = new Logger('');
const loggerPrefix = 'Failed to verify jwt::';

const privateKey: string = '-----BEGIN RSA PRIVATE KEY-----\n'
  + 'MIIEowIBAAKCAQEA0Ttga33B1yX4w77NbpKyNYDNSVCo8j+RlZaZ9tI+KfkV1d+t\n'
  + 'fsvI9ZPAheP11FoN52ceBaY5ltelHW+IKwCfyT0orLdsxLgowaXki9woF1Azvcg2\n'
  + 'JVxQLv9aVjjAvy3CZFIG/EeN7J3nsyCXGnu1yMEbnvkWxA88//Q6HQ2K9wqfApkQ\n'
  + '0LNlsK0YHz/sfjHNvRKxnbAJk7D5fUhZunPZXOPHXFgA5SvLvMaNIXduMKJh4OMf\n'
  + 'uoLdJowXJAR9j31Mqz/is4FMhm/9Mq7vZZ+uF09htRvIR8tRY28oJuW1gKWyg7cQ\n'
  + 'QpnjHgFyG3XLXWAeXclWqyh/LfjyHQjrYhyeFwIDAQABAoIBAHMqdJsWAGEVNIVB\n'
  + '+792HYNXnydQr32PwemNmLeD59WglgU/9jZJoxaROjI4VLKK0wZg+uRvJ1nA3tCB\n'
  + '+Hh7Anh5Im9XExaAq2ZTkqXtC2AxtBktH6iW1EfaI/Y7jNRuMoaXo+Ku3A62p7cw\n'
  + 'JBvepiOXL0Xko0RNguz7mBUvxCLPhYhzn7qCbM8uXLcjsXq/YhWQwQmtMqv0sd3W\n'
  + 'Hy+8Jb2c18sqDeZIBne4dWD6qPClPEOsrq9gPTkl0DjbT27oVc2u1p4HMNm5BJIh\n'
  + 'u3rMSxnZHUd7Axj1FgyLIOHl63UhaiaA1aPe/fLiVIGOA1jBZrpbnjgqDy9Uxyn6\n'
  + 'eydbiwECgYEA9mtRydz22idyUOlBCDXk+vdGBvFAucNYaNNUAXUJ2wfPmdGgFCA7\n'
  + 'g5eQG8JC6J/FU+2AfIuz6LGr7SxMBYcsWGjFAzGqs/sJib+zzN1dPUSRn4uJNFit\n'
  + '51yQzPgBqHS6S/XBi6YAODeZDl9jiPl3FxxucqLY5NstqZFXbE0SjIECgYEA2V3r\n'
  + '7xnRAK1krY1+zkPof4kcBmjqOXjnl/oRxlXP65lEXmyNJwm/ulOIko9mElWRs8CG\n'
  + 'AxSWKaab9Gk6lc8MHjVRbuW52RGLGKq1mp6ENr4d3IBOfrNsTvD3gtNEN1JFLeF1\n'
  + 'jIbSsrbi2txr7VZ06Irac0C/ytro0QDOUoXkvpcCgYA8O0EzmToRWsD7e/g0XJAK\n'
  + 's/Q+8CtE/LWYccc/z+7HxeH9lBqPsM07Pgmwb0xRdfQSrqPQTYl9ICiJAWHXnBG/\n'
  + 'zmQRgstZ0MulCuGU+qq2thLuL3oq/F4NhjeykhA9r8J1nK1hSAMXuqdDtxcqPOfa\n'
  + 'E03/4UQotFY181uuEiytgQKBgHQT+gjHqptH/XnJFCymiySAXdz2bg6fCF5aht95\n'
  + 't/1C7gXWxlJQnHiuX0KVHZcw5wwtBePjPIWlmaceAtE5rmj7ZC9qsqK/AZ78mtql\n'
  + 'SEnLoTq9si1rN624dRUCKW25m4Py4MlYvm/9xovGJkSqZOhCLoJZ05JK8QWb/pKH\n'
  + 'Oi6lAoGBAOUN6ICpMQvzMGPgIbgS0H/gvRTnpAEs59vdgrkhlCII4tzfgvBQlVae\n'
  + 'hRcdM6GTMq5pekBPKu45eanIzwVc88P6coT4qiWYKk2jYoLBa0UV3xEAuqBMymrj\n'
  + 'X4nLcSbZtO0tcDGMfMpWF2JGYOEJQNetPozL/ICGVFyIO8yzXm8U\n'
  + '-----END RSA PRIVATE KEY-----';

const response = {
  keys: [
    {
      kid: '1234example=',
      alg: 'RS256',
      kty: 'RSA',
      e: 'AQAB',
      // eslint-disable-next-line max-len
      n: '0Ttga33B1yX4w77NbpKyNYDNSVCo8j-RlZaZ9tI-KfkV1d-tfsvI9ZPAheP11FoN52ceBaY5ltelHW-IKwCfyT0orLdsxLgowaXki9woF1Azvcg2JVxQLv9aVjjAvy3CZFIG_EeN7J3nsyCXGnu1yMEbnvkWxA88__Q6HQ2K9wqfApkQ0LNlsK0YHz_sfjHNvRKxnbAJk7D5fUhZunPZXOPHXFgA5SvLvMaNIXduMKJh4OMfuoLdJowXJAR9j31Mqz_is4FMhm_9Mq7vZZ-uF09htRvIR8tRY28oJuW1gKWyg7cQQpnjHgFyG3XLXWAeXclWqyh_LfjyHQjrYhyeFw',
      use: 'sig',
    },
  ],
};

describe('Test Cognito', () => {
  jest.mock('axios');
  beforeEach(() => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.COGNITO_CLIENT_ID = 'cognito_client_id';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    config = loadConfig();
    cognito = new Cognito(
      config.cognito.region, config.cognito.poolId, config.cognito.clientId, logger,
    );
  });

  test('getIssuer() should return url with pool id and region', () => {
    expect(cognito.getIssuer()).toBe('https://cognito-idp.cognito_region.amazonaws.com/cognito_pool_id');
  });

  test('verify() should return true for correct jwt', async () => {
    const payload: JwtPayload = {
      iss: cognito.getIssuer(),
      token_use: 'access',
      client_id: config.cognito.clientId,
    };
    const token = jwt.sign(payload, privateKey, { expiresIn: '1h', keyid: '1234example=', algorithm: 'RS256' });
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await cognito.verify(token, decodedToken)).toBe(true);
  });

  test('verify() should return false for expired jtw', async () => {
    const payload: JwtPayload = {
      iss: cognito.getIssuer(),
      token_use: 'access',
      client_id: config.cognito.clientId,
    };
    const token: string = jwt.sign(payload, privateKey, {
      expiresIn: -60,
      keyid: '1234example=',
      algorithm: 'RS256',
    }) as string;
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} jwt expired`,
    );
  });

  test('verify() should return false for invalid client_id', async () => {
    const payload: JwtPayload = {
      iss: cognito.getIssuer(),
      token_use: 'access',
      client_id: 'incorrect',
    };
    const token: string = jwt.sign(payload, privateKey, {
      expiresIn: '1h',
      keyid: '1234example=',
      algorithm: 'RS256',
    }) as string;
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} contains invalid 'client_id'`,
    );
  });

  test('verify() should return false for invalid token_use', async () => {
    const payload: JwtPayload = {
      iss: cognito.getIssuer(),
      token_use: 'incorrect',
      client_id: config.cognito.clientId,
    };
    const token: string = jwt.sign(payload, privateKey, {
      expiresIn: '1h',
      keyid: '1234example=',
      algorithm: 'RS256',
    }) as string;
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} contains invalid 'token_use'`,
    );
  });

  test('verify() should return false for invalid key', async () => {
    const payload: JwtPayload = {
      iss: cognito.getIssuer(),
      token_use: 'incorrect',
      client_id: config.cognito.clientId,
    };
    const token: string = jwt.sign(payload, privateKey, {
      expiresIn: '1h',
      keyid: 'key',
      algorithm: 'RS256',
    }) as string;
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    mockedAxios.get.mockResolvedValue({ data: response });

    expect(await cognito.verify(token, decodedToken)).toBe(false);
    expect(console.info).toHaveBeenLastCalledWith(
      logger.logFormat,
      `${loggerPrefix} no public key with ID 'key' under pool cognito_pool_id`,
    );
  });
});
