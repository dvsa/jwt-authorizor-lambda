import type { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context } from 'aws-lambda';
import { Action } from 'iam-policy-generator';
import { Effect } from 'iam-policy-generator/lib/PolicyFactory';
import { loadConfig } from '../util/configuration';
import { Cognito } from '../services/cognito';
import { Azure } from '../services/azure';
import { Logger } from '../util/logger';
import { TokenVerifier } from '../services/tokenVerifier';

/**
 * Lambda Handler
 *
 * @param {APIGatewayTokenAuthorizerEvent} event
 * @param {Context} context
 * @returns {Promise<APIGatewayAuthorizerResult>}
 */
export const handler = async (event: APIGatewayTokenAuthorizerEvent, context: Context):
Promise<APIGatewayAuthorizerResult> => {
  const config = loadConfig();
  const logger = new Logger(context.awsRequestId);
  const verifier = new TokenVerifier(
    new Cognito(config.cognito.region, config.cognito.poolId, config.cognito.clientIds, logger),
    new Azure(config.azure.tenantId, config.azure.clientId, logger),
    logger,
  );

  const arnParts = event.methodArn.split(':');
  const apiGatewayArn = arnParts[5].split('/');

  // Create wildcard resource
  const resourceArn = `${arnParts[0]}:${arnParts[1]}:${arnParts[2]}:${arnParts[3]}:${arnParts[4]}:${apiGatewayArn[0]}/*/*`;

  if (!event.authorizationToken.trim()) {
    logger.error('no caller-supplied-token (no authorization header on original request)');
    return unauthorisedPolicy(resourceArn);
  }

  const [bearerPrefix, token] = event.authorizationToken.split(' ');
  if (bearerPrefix !== 'Bearer') {
    logger.error("caller-supplied-token must start with 'Bearer ' (case-sensitive)");
    return unauthorisedPolicy(resourceArn);
  }

  if (!token || !token.trim()) {
    logger.error("'Bearer ' prefix present, but token is blank or missing");
    return unauthorisedPolicy(resourceArn);
  }

  if (await verifier.verify(token)) {
    return authorisedPolicy(resourceArn);
  }

  return unauthorisedPolicy(resourceArn);
};

const authorisedPolicy = (arn: string): APIGatewayAuthorizerResult => ({
  principalId: 'Authorised',
  policyDocument: {
    Version: '2012-10-17',
    Statement: [{
      Effect: Effect.ALLOW,
      Action: Action.API_GATEWAY.INVOKE,
      Resource: arn,
    }],
  },
});

const unauthorisedPolicy = (arn: string): APIGatewayAuthorizerResult => ({
  principalId: 'Unauthorised',
  policyDocument: {
    Version: '2012-10-17',
    Statement: [{
      Effect: Effect.DENY,
      Action: Action.API_GATEWAY.INVOKE,
      Resource: arn,
    }],
  },
});
