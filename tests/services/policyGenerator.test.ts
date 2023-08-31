/* eslint-disable @typescript-eslint/dot-notation */
import { APIGatewayAuthorizerResult, Statement } from 'aws-lambda';
import { PolicyGenerator } from '../../src/services/policyGenerator';
import { Logger } from '../../src/util/logger';

jest.mock('../../src/util/logger');

describe('PolicyGenerator', () => {
  let policyGenerator: PolicyGenerator;

  const EVENT_ARN = 'arn:aws:execute-api:eu-west-2:123456789012:/prod/POST/path';

  const PERMISSIONS_CONFIG = [
    {
      role: 'FirstRole',
      authorisedEndpoints: [
        {
          httpVerb: 'GET',
          url: '/endpoint/one',
        }, {
          httpVerb: 'POST',
          url: 'endpoint/two',
        },
      ],
    },
    {
      role: 'SecondRole',
      authorisedEndpoints: [
        {
          httpVerb: 'GET',
          url: '/endpoint/three',
        },
      ],
    },
  ];

  beforeEach(() => {
    policyGenerator = new PolicyGenerator(new Logger(''));
  });

  describe('generateAuthorisedPolicy', () => {
    test('should return an allow policy with wildcard ARN', () => {
      const result: APIGatewayAuthorizerResult = policyGenerator.generateAuthorisedPolicy(EVENT_ARN);

      const statement: Statement = result.policyDocument.Statement.pop();

      expect(result.principalId).toBe('Authorised');
      expect(result.policyDocument.Version).toBe('2012-10-17');
      expect(statement.Effect).toBe('Allow');
      expect(statement['Action']).toBe('execute-api:Invoke');
      expect(statement['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/*');
    });
  });

  describe('generateUnauthorisedPolicy', () => {
    test('should return an allow policy with wildcard ARN', () => {
      const result: APIGatewayAuthorizerResult = policyGenerator.generateUnauthorisedPolicy(EVENT_ARN);

      const statement: Statement = result.policyDocument.Statement.pop();

      expect(result.principalId).toBe('Unauthorised');
      expect(result.policyDocument.Version).toBe('2012-10-17');
      expect(statement.Effect).toBe('Deny');
      expect(statement['Action']).toBe('execute-api:Invoke');
      expect(statement['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/*');
    });
  });

  describe('generateConfigurationFilePolicy', () => {
    test('should return an allow policy with specific ARNs for the given roles', () => {
      const result: APIGatewayAuthorizerResult = policyGenerator.generateConfigurationFilePolicy(PERMISSIONS_CONFIG, ['FirstRole', 'SecondRole'], EVENT_ARN);

      expect(result.principalId).toBe('Authorised');
      expect(result.policyDocument.Version).toBe('2012-10-17');

      expect(result.policyDocument.Statement).toHaveLength(3);

      expect(result.policyDocument.Statement[0].Effect).toBe('Allow');
      expect(result.policyDocument.Statement[0]['Action']).toBe('execute-api:Invoke');
      expect(result.policyDocument.Statement[0]['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/GET/endpoint/one');

      expect(result.policyDocument.Statement[1].Effect).toBe('Allow');
      expect(result.policyDocument.Statement[1]['Action']).toBe('execute-api:Invoke');
      expect(result.policyDocument.Statement[1]['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/POST/endpoint/two');

      expect(result.policyDocument.Statement[2].Effect).toBe('Allow');
      expect(result.policyDocument.Statement[2]['Action']).toBe('execute-api:Invoke');
      expect(result.policyDocument.Statement[2]['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/GET/endpoint/three');
    });

    test('should return an allow policy with specific ARNs for the given roles only', () => {
      const result: APIGatewayAuthorizerResult = policyGenerator.generateConfigurationFilePolicy(PERMISSIONS_CONFIG, ['FirstRole'], EVENT_ARN);

      expect(result.principalId).toBe('Authorised');
      expect(result.policyDocument.Version).toBe('2012-10-17');

      expect(result.policyDocument.Statement).toHaveLength(2);

      expect(result.policyDocument.Statement[0].Effect).toBe('Allow');
      expect(result.policyDocument.Statement[0]['Action']).toBe('execute-api:Invoke');
      expect(result.policyDocument.Statement[0]['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/GET/endpoint/one');

      expect(result.policyDocument.Statement[1].Effect).toBe('Allow');
      expect(result.policyDocument.Statement[1]['Action']).toBe('execute-api:Invoke');
      expect(result.policyDocument.Statement[1]['Resource']).toBe('arn:aws:execute-api:eu-west-2:123456789012:/*/POST/endpoint/two');
    });

    test('should return undefined when role does not exist in config', () => {
      const result: APIGatewayAuthorizerResult = policyGenerator.generateConfigurationFilePolicy(PERMISSIONS_CONFIG, ['UnknownRole'], EVENT_ARN);

      expect(result).toBeUndefined();
    });
  });
});
