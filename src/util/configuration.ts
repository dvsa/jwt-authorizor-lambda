import { Configuration } from '../types/configuration';

const config: Configuration = {
  cognito: {
    poolId: null,
    region: null,
    clientId: null,
  },
  azure: {
    tenantId: null,
    clientId: null,
  },
};

export const loadConfig = (): Configuration => {
  const errors = [];

  config.cognito.poolId = process.env.COGNITO_POOL_ID || '';
  if (!config.cognito.poolId) {
    errors.push('COGNITO_POOL_ID');
  }

  config.cognito.region = process.env.COGNITO_REGION || '';
  if (!config.cognito.region) {
    errors.push('COGNITO_REGION');
  }

  config.cognito.clientId = process.env.COGNITO_CLIENT_ID || '';
  if (!config.cognito.clientId) {
    errors.push('COGNITO_CLIENT_ID');
  }

  config.azure.tenantId = process.env.AZURE_TENANT_ID || '';
  if (!config.azure.tenantId) {
    errors.push('AZURE_TENANT_ID');
  }

  config.azure.clientId = process.env.AZURE_CLIENT_ID || '';
  if (!config.azure.clientId) {
    errors.push('AZURE_CLIENT_ID');
  }

  if (errors.length !== 0) {
    throw new Error(`Required env vars are missing: ${JSON.stringify(errors)}`);
  }

  return config;
};
