import { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context } from 'aws-lambda';
import { v4 } from 'uuid';
import { handler } from '../../src/handler/apiGatewayTokenAuthorizerEvent';
import { TokenVerifier } from '../../src/services/tokenVerifier';

jest.mock('../../src/util/logger');
jest.mock('../../src/services/tokenVerifier');

describe('Test apiGatewayTokenAuthorizerEvent', () => {
  const OLD_ENV = process.env;

  beforeAll(() => {
    process.env.COGNITO_POOL_ID = 'pool_id';
    process.env.COGNITO_REGION = 'region';
    process.env.COGNITO_CLIENT_ID_1 = 'client_id';
    process.env.AZURE_TENANT_ID = 'tenant_id';
    process.env.AZURE_CLIENT_ID = 'client_id';
  });

  beforeEach(() => {
    (TokenVerifier.prototype as jest.Mocked<TokenVerifier>).verify.mockResolvedValue(true);
  });

  afterEach(() => {
    jest.resetAllMocks();

    process.env = OLD_ENV;
  });

  test('Returns unauthorisedPolicy when authorizationToken not supplied', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: '',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect).toBe('Deny');
  });

  test('Returns unauthorisedPolicy when authorizationToken is missing bearer', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ.'
        + '_yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe('Deny');
  });

  test('Returns unauthorisedPolicy when authorizationToken is missing token', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe('Deny');
  });

  test('Returns unauthorisedPolicy when jwt is invalid', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: '',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe('Deny');
  });

  test('Returns authorisedPolicy when jwt is valid', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ.'
        + '_yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect).toBe('Allow');
    expect(TokenVerifier.prototype.verify).toHaveBeenCalled();
  });

  test('Returns authorisedPolicy when "IS_MOCK_AUTHORISER" is set valid and verify not called', async () => {
    process.env = { ...OLD_ENV, IS_MOCK: 'true' };

    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ._yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
      methodArn: 'arn:aws:execute-api:eu-west-1:123456789:GET',
    };

    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect).toBe('Allow');
    expect(TokenVerifier.prototype.verify).not.toHaveBeenCalled();
  });
});
