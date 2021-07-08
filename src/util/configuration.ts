import { Configuration } from '../types/configuration';

export const loadConfig = (): Configuration => {
  const errors = [];
  [
    'AZURE_CLIENT_ID',
    'AZURE_TENANT_ID',
    'COGNITO_POOL_ID',
    'COGNITO_REGION',
  ].forEach((envVar) => {
    if (!process.env[`${envVar}`]) {
      errors.push(envVar);
    }
  });

  if (errors.length !== 0) {
    throw new Error(`Required env vars are missing: ${JSON.stringify(errors)}`);
  }

  const cognitoClientIds: string[] = [];

  Object.keys(process.env).forEach((key) => {
    if (key.match(/COGNITO_CLIENT_ID_[0-9]*/g)) {
      cognitoClientIds.push(process.env[`${key}`]);
    }
  });

  if (cognitoClientIds.length === 0) {
    throw new Error('Missing cognito client id environment variables of pattern: COGNITO_CLIENT_ID_[0-9]*');
  }

  return {
    azure: {
      clientId: process.env.AZURE_CLIENT_ID,
      tenantId: process.env.AZURE_TENANT_ID,
    },
    cognito: {
      clientIds: cognitoClientIds,
      poolId: process.env.COGNITO_POOL_ID,
      region: process.env.COGNITO_REGION,
    },
  };
};
