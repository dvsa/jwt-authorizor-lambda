import type { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent } from 'aws-lambda';
import * as jwt from 'jsonwebtoken';
import { PolicyStatementFactory } from 'iam-policy-generator';
import { Effect } from 'iam-policy-generator/lib/PolicyFactory';
import * as azure from '../services/azure';
import * as cognito from '../services/cognito';

/**
 * Lambda Handler
 *
 * @param {APIGatewayTokenAuthorizerEvent} event
 * @returns {Promise<APIGatewayAuthorizerResult>}
 */
export const handler = async (event: APIGatewayTokenAuthorizerEvent): Promise<APIGatewayAuthorizerResult> => {
  const cognitoPoolId: string = process.env.COGNITO_POOL_ID || '';
  if (!cognitoPoolId) {
    throw new Error('env var required for cognito pool');
  }

  const cognitoRegion: string = process.env.COGNITO_REGION || '';
  if (!cognitoRegion) {
    throw new Error('env var required for cognito region');
  }

  const azureTenantId: string = process.env.AZURE_TENANT_ID || '';
  if (!azureTenantId) {
    throw new Error('env var required for azure tenant id');
  }

  const rawToken: string = event.authorizationToken;
  const decodedToken = jwt.decode(rawToken, { complete: true });
  const issuer: string = decodedToken.payload.iss;
  const keyId: string = decodedToken.header.kid;

  let key: string;
  if (issuer.includes('amazon')) {
    key = await cognito.getCertificateChain(cognitoRegion, cognitoPoolId, keyId);
  } else if (issuer.includes('windows')) {
    key = await azure.getCertificateChain(azureTenantId, keyId);
  }

  try {
    jwt.verify(rawToken, key);
    return authorisedPolicy();
  } catch (err) {
    return unauthorisedPolicy();
  }
};

const unauthorisedPolicy = (): APIGatewayAuthorizerResult => {
  const statement = new PolicyStatementFactory()
    .setEffect(Effect.DENY)
    .build();

  return {
    principalId: 'Unauthorised',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [statement.toStatementJson()],
    },
  };
};

const authorisedPolicy = (): APIGatewayAuthorizerResult => {
  const statement = new PolicyStatementFactory()
    .setEffect(Effect.ALLOW)
    .build();

  return {
    principalId: 'Authorised',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [statement.toStatementJson()],
    },
  };
};
