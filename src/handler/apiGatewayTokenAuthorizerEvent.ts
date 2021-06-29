import type {
  APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Callback, Context,
} from 'aws-lambda';
import * as jwt from 'jsonwebtoken';
import { Action, PolicyStatementFactory } from 'iam-policy-generator';
import { Effect } from 'iam-policy-generator/lib/PolicyFactory';
import * as azure from '../services/azure';
import * as cognito from '../services/cognito';
import { AuthorizerConfig, loadConfig } from '../services/configuration';

/**
 * Lambda Handler
 *
 * @param {APIGatewayTokenAuthorizerEvent} event
 * @returns {Promise<APIGatewayAuthorizerResult>}
 */
export const handler = async (event: APIGatewayTokenAuthorizerEvent, context: Context, callback: Callback):
Promise<APIGatewayAuthorizerResult> => {
  const config: AuthorizerConfig = loadConfig();

  azure.setCredentials(config.azure.tenantId, config.azure.clientId);
  cognito.setCredentials(config.cognito.region, config.cognito.poolId, config.cognito.clientId);

  const rawToken: string = event.authorizationToken;
  const decodedToken = jwt.decode(rawToken, { complete: true });

  if (!decodedToken) {
    throw new Error('Failed decoding jwt');
  }

  let tokenType: any;

  switch (decodedToken.payload.iss) {
    case cognito.getIssuer():
      tokenType = cognito;
      break;
    case azure.getIssuer():
      tokenType = azure;
      break;
    default:
      callback('Token issuer not accepted');
  }

  try {
    await tokenType.verify(rawToken, decodedToken);
  } catch (err) {
    callback(err.message);
  }

  return authorisedPolicy(event.methodArn);
};

const authorisedPolicy = (arn: string): APIGatewayAuthorizerResult => {
  const statement = new PolicyStatementFactory()
    .setEffect(Effect.ALLOW)
    .addAction(Action.API_GATEWAY.INVOKE)
    .addResource(arn)
    .build();

  return {
    principalId: 'Authorised',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [statement.toStatementJson()],
    },
  };
};