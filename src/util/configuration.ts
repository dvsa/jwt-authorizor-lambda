import { Configuration } from '../types/configuration';

export const loadConfig = (): Configuration => {
  const errors = [];

  [
    'AZURE_CLIENT_ID',
    'AZURE_TENANT_ID',
    'COGNITO_CLIENT_ID',
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

  return {
    azure: {
      clientId: process.env.AZURE_CLIENT_ID,
      tenantId: process.env.AZURE_TENANT_ID,
    },
    cognito: {
      clientId: process.env.COGNITO_CLIENT_ID,
      poolId: process.env.COGNITO_POOL_ID,
      region: process.env.COGNITO_REGION,
    },
  };
};
