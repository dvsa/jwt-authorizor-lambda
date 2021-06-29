const config: AuthorizerConfig = {
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

export interface AuthorizerConfig {
  cognito: CognitoConfig
  azure: AzureConfig
}

export interface CognitoConfig {
  poolId: string,
  region: string,
  clientId: string
}

export interface AzureConfig {
  tenantId: string,
  clientId: string
}

export const loadConfig = (): AuthorizerConfig => {

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
