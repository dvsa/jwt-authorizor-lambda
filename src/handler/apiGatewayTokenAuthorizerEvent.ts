import type {
  APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Callback, Context,
} from 'aws-lambda';
import * as jwt from 'jsonwebtoken';
import { Action, PolicyStatementFactory } from 'iam-policy-generator';
import { Effect } from 'iam-policy-generator/lib/PolicyFactory';
import * as azure from '../services/azure';
import * as cognito from '../services/cognito';

/**
 * Lambda Handler
 *
 * @param {APIGatewayTokenAuthorizerEvent} event
 * @returns {Promise<APIGatewayAuthorizerResult>}
 */
export const handler = async (event: APIGatewayTokenAuthorizerEvent, context: Context, callback: Callback):
Promise<APIGatewayAuthorizerResult> => {
  const cognitoPoolId: string = process.env.COGNITO_POOL_ID || '';
  if (!cognitoPoolId) {
    throw new Error('env var required for cognito pool');
  }

  const cognitoRegion: string = process.env.COGNITO_REGION || '';
  if (!cognitoRegion) {
    throw new Error('env var required for cognito region');
  }

  const cognitoClientId: string = process.env.COGNITO_CLIENT_ID || '';
  if (!cognitoClientId) {
    throw new Error('env var required for cognito client id');
  }

  cognito.setCredentials(cognitoRegion, cognitoPoolId, cognitoClientId);

  const azureTenantId: string = process.env.AZURE_TENANT_ID || '';
  if (!azureTenantId) {
    throw new Error('env var required for azure tenant id');
  }

  const azureClientId: string = process.env.AZURE_CLIENT_ID || '';
  if (!azureClientId) {
    throw new Error('env var required for azure client id');
  }

  azure.setCredentials(azureTenantId, azureClientId);

  const rawToken: string = event.authorizationToken;
  const decodedToken = jwt.decode(rawToken, { complete: true });

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
