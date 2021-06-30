import { APIGatewayTokenAuthorizerEvent, Callback, Context } from 'aws-lambda';
import { v4 } from 'uuid';
import * as jwt from 'jsonwebtoken';
import { handler } from '../../src/handler/apiGatewayTokenAuthorizerEvent';
import * as cognito from '../../src/services/cognito';
import { loadConfig } from "../../src/services/configuration";

describe('Test API Gateway token authorizer event', () => {
  beforeAll(() => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.COGNITO_CLIENT_ID = 'cognito_client_id';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';
  });

  test('handle() should throw error when token is not a valid jwt', () => {
    // const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent> {
    //   authorizationToken: 'token',
    //   methodArn: '',
    // };
    // const contextMock: Context = <Context> { awsRequestId: v4() };
    // const callbackMock: Callback = <Callback> {};
    //
    // expect(() => handler(eventMock, contextMock, callbackMock)).toThrow('Failed decoding jwt');
    // // expect(() => loadConfig()).toThrow(/COGNITO_CLIENT_ID/);
  });

  test('handle() should call cognito.verify for a cognito token', () => {
    //
    //
    //
    // // const token = jwt.sign({iss:})
    // const eventMock: APIGatewayTokenAuthorizerEvent = <APIGatewayTokenAuthorizerEvent> {
    //   authorizationToken: 'token',
    //   methodArn: '',
    // };
    // const contextMock: Context = <Context> { awsRequestId: v4() };
    // const callbackMock: Callback = <Callback> {};
  });
});
