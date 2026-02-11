import { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context } from 'aws-lambda';
import { v4 } from 'uuid';
import { Jwt } from 'jsonwebtoken';
import { handler } from '../../src/handler/apiGatewayTokenAuthorizerEvent';
import { TokenVerifier } from '../../src/services/tokenVerifier';
import { PolicyGenerator } from '../../src/services/policyGenerator';
import { PermissionsConfigReader } from '../../src/services/permissionsConfigReader';

jest.mock('../../src/util/logger');
jest.mock('../../src/services/tokenVerifier');
jest.mock('../../src/services/policyGenerator');
jest.mock('../../src/services/permissionsConfigReader');

describe('Test apiGatewayTokenAuthorizerEvent', () => {
  const OLD_ENV = process.env;

  const POLICY: APIGatewayAuthorizerResult = {
    principalId: 'Authorised',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow',
        Action: 'execute-api:Invoke',
        Resource: 'arn:aws:test',
      }],
    },
  };

  const VALID_EVENT_MOCK: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
    authorizationToken: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ._yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
    methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
  };

  const CONTEXT_MOCK: Context = <Context>{ awsRequestId: v4() };

  const TOKEN: Jwt = {
    header: { alg: '' },
    signature: '',
    payload: {
      roles: ['FirstRole', 'SecondRole'],
    },
  };

  const COGNITO_TOKEN: Jwt = {
    header: { alg: '' },
    signature: '',
    payload: {
      'cognito:groups': ['FirstGroup', 'SecondGroup'],
    },
  };

  beforeAll(() => {
    process.env.COGNITO_POOL_ID = 'pool_id';
    process.env.COGNITO_REGION = 'region';
    process.env.COGNITO_CLIENT_ID_1 = 'client_id';
    process.env.AZURE_TENANT_ID = 'tenant_id';
    process.env.AZURE_CLIENT_ID = 'client_id';
  });

  beforeEach(() => {
    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).verify.mockResolvedValue(true);
    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).getVerifiedDecodedToken.mockResolvedValue(TOKEN);
    (PolicyGenerator.prototype as jest.Mocked<PolicyGenerator>).generateAuthorisedPolicy.mockReturnValue(POLICY);
    (PolicyGenerator.prototype as jest.Mocked<PolicyGenerator>).generateUnauthorisedPolicy.mockReturnValue(POLICY);
    (PolicyGenerator.prototype as jest.Mocked<PolicyGenerator>).generateConfigurationFilePolicy.mockReturnValue(POLICY);
    (PolicyGenerator.prototype as jest.Mocked<PolicyGenerator>).generateConfigurationFilePolicyForProxy.mockReturnValue(POLICY);
    (PermissionsConfigReader.prototype as jest.Mocked<PermissionsConfigReader>).readConfigFile.mockReturnValue([]);
  });

  afterEach(() => {
    jest.resetAllMocks();

    process.env = OLD_ENV;
  });

  test('Returns generated unauthorised policy when authorizationToken not supplied', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: '',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated unauthorised policy when authorizationToken is missing bearer', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ._yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated unauthorised policy when authorizationToken is missing token', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated unauthorised policy when jwt is invalid', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer 123',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };
    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).verify.mockResolvedValue(false);

    const res: APIGatewayAuthorizerResult = await handler(eventMock, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated authorised policy when jwt is valid', async () => {
    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.verify).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateAuthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated authorised policy when "IS_MOCK" is set valid and verify not called', async () => {
    process.env = { ...OLD_ENV, IS_MOCK: 'true' };

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.verify).not.toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateAuthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated unauthorised policy when configurationFile.enabled is true but token cannot be verified and decoded', async () => {
    process.env = { ...OLD_ENV, ENABLE_CONFIGURATION_FILE: 'true', CONFIGURATION_FILE_PATH: '/path/to/file' };

    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).getVerifiedDecodedToken.mockResolvedValue(undefined);

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.getVerifiedDecodedToken).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated unauthorised policy when configurationFile.enabled is true but decoded token has string payload', async () => {
    process.env = { ...OLD_ENV, ENABLE_CONFIGURATION_FILE: 'true', CONFIGURATION_FILE_PATH: '/path/to/file' };

    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).getVerifiedDecodedToken.mockResolvedValue({ ...TOKEN, payload: 'Not a JWT Payload' });

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.getVerifiedDecodedToken).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns generated unauthorised policy when configurationFile.enabled is true but policy cannot be built from config file', async () => {
    process.env = { ...OLD_ENV, ENABLE_CONFIGURATION_FILE: 'true', CONFIGURATION_FILE_PATH: '/path/to/file' };

    (PolicyGenerator.prototype as jest.Mocked<PolicyGenerator>).generateConfigurationFilePolicy.mockReturnValue(undefined);

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.getVerifiedDecodedToken).toHaveBeenCalled();
    expect(PermissionsConfigReader.prototype.readConfigFile).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateUnauthorisedPolicy).toHaveBeenCalled();
  });

  test('Returns authorised policy generated from configuration file when configurationFile.enabled is true and cognito:groups is on the decoded token', async () => {
    process.env = { ...OLD_ENV, ENABLE_CONFIGURATION_FILE: 'true', CONFIGURATION_FILE_PATH: '/path/to/file' };

    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).getVerifiedDecodedToken.mockResolvedValue(COGNITO_TOKEN);

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.getVerifiedDecodedToken).toHaveBeenCalled();
    expect(PermissionsConfigReader.prototype.readConfigFile).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).toHaveBeenCalledWith([], ['FirstGroup', 'SecondGroup'], VALID_EVENT_MOCK.methodArn);
  });

  test('Returns authorised policy generated from configuration file when configurationFile.enabled is true and roles is on the decoded token', async () => {
    process.env = { ...OLD_ENV, ENABLE_CONFIGURATION_FILE: 'true', CONFIGURATION_FILE_PATH: '/path/to/file' };

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(res).toBe(POLICY);
    expect(TokenVerifier.prototype.getVerifiedDecodedToken).toHaveBeenCalled();
    expect(PermissionsConfigReader.prototype.readConfigFile).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).toHaveBeenCalledWith([], ['FirstRole', 'SecondRole'], VALID_EVENT_MOCK.methodArn);
  });

  test('Should call generateConfigurationFilePolicyForProxy when IS_PROXY is enabled and set to true', async () => {
    process.env = {
      ...OLD_ENV,
      IS_PROXY: 'true',
      ENABLE_CONFIGURATION_FILE: 'true',
      CONFIGURATION_FILE_PATH: '/path/to/file',
    };

    const res: APIGatewayAuthorizerResult = await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(TokenVerifier.prototype.getVerifiedDecodedToken).toHaveBeenCalled();
    expect(PermissionsConfigReader.prototype.readConfigFile).toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicyForProxy).toHaveBeenCalledWith([], ['FirstRole', 'SecondRole'], VALID_EVENT_MOCK.methodArn);
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).not.toHaveBeenCalled();
    expect(res).toBe(POLICY);
  });

  test('Should not call generateConfigurationFilePolicyForProxy when IS_PROXY is set to false or not provided', async () => {
    process.env = {
      ...OLD_ENV,
      ENABLE_CONFIGURATION_FILE: 'true',
      CONFIGURATION_FILE_PATH: '/path/to/file',
    };
    await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(PolicyGenerator.prototype.generateConfigurationFilePolicyForProxy).not.toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).toHaveBeenCalled();

    process.env = {
      ...OLD_ENV,
      IS_PROXY: 'false',
      ENABLE_CONFIGURATION_FILE: 'true',
      CONFIGURATION_FILE_PATH: '/path/to/file',
    };

    await handler(VALID_EVENT_MOCK, CONTEXT_MOCK);

    expect(PolicyGenerator.prototype.generateConfigurationFilePolicyForProxy).not.toHaveBeenCalled();
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).toHaveBeenCalled();

    expect(PolicyGenerator.prototype.generateConfigurationFilePolicyForProxy).toHaveBeenCalledTimes(0);
    expect(PolicyGenerator.prototype.generateConfigurationFilePolicy).toHaveBeenCalledTimes(2);
  });
});
