import type { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context } from 'aws-lambda';
import { loadConfig } from '../util/configuration';
import { Cognito } from '../services/cognito';
import { Azure } from '../services/azure';
import { Logger } from '../util/logger';
import { TokenVerifier } from '../services/tokenVerifier';
import { PolicyGenerator } from '../services/policyGenerator';
import { PermissionsConfigReader } from '../services/permissionsConfigReader';
import { SchemaValidator } from '../services/schemaValidator';

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
  const policyGenerator = new PolicyGenerator(logger);
  const schemaValidator = new SchemaValidator();
  const fileService = new PermissionsConfigReader(schemaValidator, logger);
  const verifier = new TokenVerifier(
    new Cognito(config.cognito.region, config.cognito.poolId, config.cognito.clientIds, logger),
    new Azure(config.azure.tenantId, config.azure.clientId, logger),
    logger,
  );

  if (!event.authorizationToken.trim()) {
    logger.error('no caller-supplied-token (no authorization header on original request)');
    return policyGenerator.generateUnauthorisedPolicy(event.methodArn);
  }

  const [bearerPrefix, token] = event.authorizationToken.split(' ');
  if (bearerPrefix !== 'Bearer') {
    logger.error("caller-supplied-token must start with 'Bearer ' (case-sensitive)");
    return policyGenerator.generateUnauthorisedPolicy(event.methodArn);
  }

  if (!token || !token.trim()) {
    logger.error("'Bearer ' prefix present, but token is blank or missing");
    return policyGenerator.generateUnauthorisedPolicy(event.methodArn);
  }

  if (process.env.IS_MOCK === 'true') {
    return policyGenerator.generateAuthorisedPolicy(event.methodArn);
  }

  if (config.configurationFile.enabled) {
    const decodedToken = await verifier.getVerifiedDecodedToken(token);

    if (!decodedToken) {
      return policyGenerator.generateUnauthorisedPolicy(event.methodArn);
    }

    const permissionsConfig = fileService.readConfigFile(config.configurationFile.filePath);
    if (typeof decodedToken.payload !== 'string') {
      const tokenPermissions = (decodedToken.payload['cognito:groups'] || decodedToken.payload.roles) as string[];

      return policyGenerator.generateConfigurationFilePolicy(permissionsConfig, tokenPermissions, event.methodArn)
        || policyGenerator.generateUnauthorisedPolicy(event.methodArn);
    }

    return policyGenerator.generateUnauthorisedPolicy(event.methodArn);
  }

  logger.info('Configuration file not enabled. Defaulting to grant / deny all endpoints');

  if (await verifier.verify(token)) {
    return policyGenerator.generateAuthorisedPolicy(event.methodArn);
  }

  return policyGenerator.generateUnauthorisedPolicy(event.methodArn);
};
