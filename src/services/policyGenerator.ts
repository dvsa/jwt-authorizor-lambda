import { APIGatewayAuthorizerResult, Statement } from 'aws-lambda';
import { Action } from 'iam-policy-generator';
import { AuthorisedEndpoint, PermissionsConfig } from '../types/configuration';

export class PolicyGenerator {
  private readonly AUTHORISED_ID = 'Authorised';

  private readonly UNAUTHORISED_ID = 'Unauthorised';

  private readonly VERSION = '2012-10-17';

  private readonly ALLOW = 'Allow';

  private readonly DENY = 'Deny';

  public generateAuthorisedPolicy(eventArn: string): APIGatewayAuthorizerResult {
    const resourceArn = this.generateWildcardArn(eventArn);

    return {
      principalId: this.AUTHORISED_ID,
      policyDocument: {
        Version: this.VERSION,
        Statement: [{
          Effect: this.ALLOW,
          Action: Action.API_GATEWAY.INVOKE,
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
          Action: Action.API_GATEWAY.INVOKE,
          Resource: resourceArn,
        }],
      },
    };
  }

  public generateConfigurationFilePolicy(configFileContents: PermissionsConfig, roles: string[], eventMethodArn: string): APIGatewayAuthorizerResult {
    let statements: Statement[] = [];

    roles.forEach((role) => {
      const items = this.generateStatementsForRole(role, configFileContents, eventMethodArn);
      statements = statements.concat(items);
    });

    if (statements.length === 0) {
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
      Action: Action.API_GATEWAY.INVOKE,
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
    const arnParts = eventMethodArn.split(':');
    const apiGatewayArn = arnParts[5].split('/');

    return `${arnParts[0]}:${arnParts[1]}:${arnParts[2]}:${arnParts[3]}:${arnParts[4]}:${apiGatewayArn[0]}`;
  }
}
