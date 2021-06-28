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
  config.cognito.poolId = process.env.COGNITO_POOL_ID || '';
  if (!config.cognito.poolId) {
    throw new Error('env var required for cognito pool id');
  }

  config.cognito.region = process.env.COGNITO_REGION || '';
  if (!config.cognito.region) {
    throw new Error('env var required for cognito region');
  }

  config.cognito.clientId = process.env.COGNITO_CLIENT_ID || '';
  if (!config.cognito.clientId) {
    throw new Error('env var required for cognito client id');
  }

  config.azure.tenantId = process.env.AZURE_TENANT_ID || '';
  if (!config.azure.tenantId) {
    throw new Error('env var required for azure tenant id');
  }

  config.azure.clientId = process.env.AZURE_CLIENT_ID || '';
  if (!config.azure.clientId) {
    throw new Error('env var required for azure client id');
  }

  return config;
};
