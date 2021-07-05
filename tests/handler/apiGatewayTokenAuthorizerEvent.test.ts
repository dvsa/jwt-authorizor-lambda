import { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context } from 'aws-lambda';
import { v4 } from 'uuid';
import { Effect } from 'iam-policy-generator/lib/PolicyFactory';
import { handler } from '../../src/handler/apiGatewayTokenAuthorizerEvent';

jest.mock('../../src/util/logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  })),
}));

jest.mock('../../src/services/tokenVerifier', () => ({
  TokenVerifier: jest.fn().mockImplementation(() => ({
    decode: () => {},
    verify: () => true,
  })),
}));

describe('Test apiGatewayTokenAuthorizerEvent', () => {
  beforeAll(() => {
    process.env.COGNITO_POOL_ID = 'pool_id';
    process.env.COGNITO_REGION = 'region';
    process.env.COGNITO_CLIENT_ID = 'client_id';
    process.env.AZURE_TENANT_ID = 'tenant_id';
    process.env.AZURE_CLIENT_ID = 'client_id';
  });

  test('Returns unauthorisedPolicy when authorizationToken not supplied', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: '',
      methodArn: 'GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect).toBe(Effect.DENY);
  });

  test('Returns unauthorisedPolicy when authorizationToken is missing bearer', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ.'
        + '_yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
      methodArn: 'GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe(Effect.DENY);
  });

  test('Returns unauthorisedPolicy when authorizationToken is missing token', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer',
      methodArn: 'GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe(Effect.DENY);
  });

  test('Returns unauthorisedPolicy when jwt is invalid', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: '',
      methodArn: 'GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe(Effect.DENY);
  });
  test('Returns authorisedPolicy when jwt is valid', async () => {
    const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent>{
      authorizationToken: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsb2NhbGhvc3QiLCJhdWQiOiJjbGllbnRfaWQifQ.'
        + '_yCp5phJj2mIJEFi3Yyr-7yiCx4zMqCXoZmYBDv6Pkc',
      methodArn: 'GET',
    };
    const contextMock: Context = <Context>{ awsRequestId: v4() };

    const res: APIGatewayAuthorizerResult = await handler(eventMock, contextMock);
    const statement = res.policyDocument.Statement.pop();

    expect(statement.Effect)
      .toBe(Effect.ALLOW);
  });
});
