import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import * as jwt from 'jsonwebtoken';
import { int } from 'aws-sdk/clients/datapipeline';
import { createLogger, Logger } from '../util/logger';
import * as azure from '../services/azure';
import * as cognito from '../services/cognito';

/**
 * Lambda Handler
 *
 * @param {APIGatewayProxyEvent} event
 * @param {Context} context
 * @returns {Promise<APIGatewayProxyResult>}
 */
export const handler = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
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

  const logger: Logger = createLogger(event, context);
  const queryParams: Record<string, string> = event.queryStringParameters;

  const { token } = queryParams;
  const decoded = jwt.decode(token, { complete: true });

  const issuer: string = decoded.payload.iss;
  const keyId: string = decoded.header.kid;

  let key: string;
  if (issuer.includes('amazon')) {
    key = await cognito.getCertificateChain(cognitoRegion, cognitoPoolId, keyId);
  } else if (issuer.includes('windows')) {
    key = await azure.getCertificateChain(azureTenantId, keyId);
  }

  let valid;
  let statusCode: int = 200;
  try {
    valid = jwt.verify(token, key);
    return Promise.resolve({
      statusCode,
      body: JSON.stringify(valid),
    });
  } catch (err) {
    statusCode = 500;
    const message = err.message;
    return Promise.resolve({
      statusCode,
      body: JSON.stringify(message),
    });
  }
};
