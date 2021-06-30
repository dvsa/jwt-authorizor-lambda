import type {
  APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Callback, Context,
} from 'aws-lambda';
import { decode, verify } from 'jsonwebtoken';
import { Action, PolicyStatementFactory } from 'iam-policy-generator';
import { Effect } from 'iam-policy-generator/lib/PolicyFactory';
import { AuthorizerConfig, loadConfig } from '../services/configuration';
import { Cognito } from '../services/cognito';
import { Azure } from '../services/azure';
import { Jwt } from '../types/types';
import { createLogger, Logger } from '../util/logger';

/**
 * Lambda Handler
 *
 * @param {APIGatewayTokenAuthorizerEvent} event
 * @returns {Promise<APIGatewayAuthorizerResult>}
 */
export const handler = async (event: APIGatewayTokenAuthorizerEvent, context: Context, callback: Callback):
Promise<APIGatewayAuthorizerResult> => {
  const config: AuthorizerConfig = loadConfig();
  const logger: Logger = createLogger(context);
  const cognito: Cognito = new Cognito(config.cognito.region, config.cognito.poolId, config.cognito.clientId, logger);
  const azure: Azure = new Azure(config.azure.tenantId, config.azure.clientId, logger);
  const rawToken: string = event.authorizationToken;
  const decodedToken: Jwt = decode(rawToken, { complete: true }) as Jwt;

  if (!decodedToken) {
    throw new Error('Failed decoding jwt');
  }

  let tokenType: Azure | Cognito;

  switch (decodedToken.payload.iss) {
    case cognito.getIssuer():
      tokenType = cognito;
      break;
    case azure.getIssuer():
      tokenType = azure;
      break;
    default:
      callback(`Token issuer: '${decodedToken.payload.iss}' not accepted`);
  }
  let validToken: boolean;
  try {
    validToken = await tokenType.verify(rawToken, decodedToken);
  } catch (err) {
    callback(err.message);
  }

  if (!validToken) {
    callback('Invalid jwt provided');
  }

  return authorisedPolicy(event.methodArn);
};

const authorisedPolicy = (arn: string): APIGatewayAuthorizerResult => {
  return {
    principalId: 'Authorised',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Effect: Effect.ALLOW,
        Action: Action.API_GATEWAY.INVOKE,
        Resource: arn,
      }],
    },
  };
};
