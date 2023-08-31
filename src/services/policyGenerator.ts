import { APIGatewayAuthorizerResult, Statement } from 'aws-lambda';
import { AuthorisedEndpoint, PermissionsConfig } from '../types/configuration';
import { Logger } from '../util/logger';

export class PolicyGenerator {
  private readonly AUTHORISED_ID = 'Authorised';

  private readonly UNAUTHORISED_ID = 'Unauthorised';

  private readonly VERSION = '2012-10-17';

  private readonly ALLOW = 'Allow';

  private readonly DENY = 'Deny';

  private readonly INVOKE_ACTION = 'execute-api:Invoke';

  logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  public generateAuthorisedPolicy(eventArn: string): APIGatewayAuthorizerResult {
    const resourceArn = this.generateWildcardArn(eventArn);

    return {
      principalId: this.AUTHORISED_ID,
      policyDocument: {
        Version: this.VERSION,
        Statement: [{
          Effect: this.ALLOW,
          Action: this.INVOKE_ACTION,
          Resource: resourceArn,
        }],
      },
    };
  }

  public generateUnauthorisedPolicy(eventArn: string): APIGatewayAuthorizerResult {
    const resourceArn = this.generateWildcardArn(eventArn);

    return {
      principalId: this.UNAUTHORISED_ID,
      policyDocument: {
        Version: this.VERSION,
        Statement: [{
          Effect: this.DENY,
          Action: this.INVOKE_ACTION,
          Resource: resourceArn,
        }],
      },
    };
  }

  public generateConfigurationFilePolicy(configFileContents: PermissionsConfig, roles: string[], eventMethodArn: string): APIGatewayAuthorizerResult {
    const statements = roles.flatMap((role) => this.generateStatementsForRole(role, configFileContents, eventMethodArn));

    if (statements.length === 0) {
      this.logger.info('No permissions config found for roles');
      return undefined;
    }

    return {
      principalId: this.AUTHORISED_ID,
      policyDocument: {
        Version: this.VERSION,
        Statement: statements,
      },
    };
  }

  private generateStatementsForRole(role: string, configFileContents: PermissionsConfig, eventMethodArn: string): Statement[] {
    const roleConfig = configFileContents.find((config) => config.role === role);

    return roleConfig ? roleConfig.authorisedEndpoints.map((endpoint) => this.buildStatement(endpoint, eventMethodArn)) : [];
  }

  private buildStatement(endpoint: AuthorisedEndpoint, eventMethodArn: string): Statement {
    const arn = this.generateResourceSpecificArn(endpoint, eventMethodArn);

    return {
      Effect: this.ALLOW,
      Action: this.INVOKE_ACTION,
      Resource: arn,
    };
  }

  private generateWildcardArn(eventMethodArn: string): string {
    const arnPrefix = this.generateArnPrefix(eventMethodArn);

    return `${arnPrefix}/*/*`;
  }

  private generateResourceSpecificArn(endpoint: AuthorisedEndpoint, eventMethodArn: string): string {
    const arnPrefix = this.generateArnPrefix(eventMethodArn);

    const endpointUrl = endpoint.url.startsWith('/') ? endpoint.url : `/${endpoint.url}`;

    return `${arnPrefix}/*/${endpoint.httpVerb}${endpointUrl}`;
  }

  private generateArnPrefix(eventMethodArn: string): string {
    const [arn, partition, service, region, accountId, resource] = eventMethodArn.split(':');
    const [apiGatewayId] = resource.split('/');

    return `${arn}:${partition}:${service}:${region}:${accountId}:${apiGatewayId}`;
  }
}
