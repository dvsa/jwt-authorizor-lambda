import type { APIGatewayAuthorizerResult, Statement } from 'aws-lambda';
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

  /**
   * Generates an API Gateway authorizer policy by evaluating the requested HTTP
   * method and path against a permissions configuration and the user's roles.
   *
   * If the route the user is trying to access matches the role they have then an "Allow" policy is returned;
   * otherwise an explicit "Deny" policy is generated.
   *
   * @param configFileContents - Parsed permissions configuration defining which
   * roles are allowed to access which HTTP verbs and paths
   * @param userRoles - List of roles associated with the requesting user
   * @param eventMethodArn - API Gateway method ARN representing the incoming request
   * @returns An API Gateway authorizer result containing a policy document
   *          indicating whether access is allowed or denied
   */
  public generateConfigurationFilePolicyForProxy(configFileContents: PermissionsConfig, userRoles: string[], eventMethodArn: string): APIGatewayAuthorizerResult {
    // Extract verb + path from ARN
    const [, , , , , resource] = eventMethodArn.split(':');
    const [, , httpVerb, ...pathParts] = resource.split('/');
    const requestPath = `/${pathParts.join('/')}`;

    const isAllowed = configFileContents.some((roleConfig) => userRoles.includes(roleConfig.role)
        && roleConfig.authorisedEndpoints.some((ep) => {
          if (ep.httpVerb !== httpVerb) return false;

          // Handle wildcard matching / path params
          if (ep.url.endsWith('*')) {
            // remove '*'
            const basePath = ep.url.slice(0, -1);
            return requestPath.startsWith(basePath);
          }
          return ep.url === requestPath;
        }));

    this.logger.info(`User ${isAllowed ? '' : 'not '}authorised to access ${requestPath} with the roles: ${JSON.stringify(userRoles)}`);

    return {
      principalId: isAllowed ? this.AUTHORISED_ID : this.UNAUTHORISED_ID,
      policyDocument: {
        Version: this.VERSION,
        Statement: [{
          Effect: isAllowed ? this.ALLOW : this.DENY,
          Action: this.INVOKE_ACTION,
          Resource: eventMethodArn,
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
