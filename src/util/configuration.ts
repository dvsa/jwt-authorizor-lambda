import { Configuration } from '../types/configuration';

export const loadConfig = (): Configuration => {
  const errors = [];
  [
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

  if (process.env.ENABLE_CONFIGURATION_FILE === 'true' && !process.env.CONFIGURATION_FILE_PATH) {
    throw new Error('CONFIGURATION_FILE_PATH must be set when ENABLE_CONFIGURATION_FILE is true');
  }

  const cognitoClientIds: string[] = [];
  const azureClientIds: string[] = [];

  Object.keys(process.env).forEach((key) => {
    // allow up to 9999 cognito client ids
    const cognitoRegex = /COGNITO_CLIENT_ID(_[0-9]{,4})?/g;
    if (key.match(cognitoRegex)) {
      const envValue = process.env[`${key}`];
      if (envValue) {
        cognitoClientIds.push(envValue);
      }
    }

    // allow up to 9999 azure client ids
    const azureRegex = /AZURE_CLIENT_ID(_[0-9]{,4})?/g;
    if (key.match(azureRegex)) {
      const envValue = process.env[`${key}`];
      if (envValue) {
        azureClientIds.push(envValue);
      }
    }
  });

  if (cognitoClientIds.length === 0) {
    throw new Error('Missing cognito client id environment variables of pattern: COGNITO_CLIENT_ID_[0-9]*');
  }

  if (azureClientIds.length === 0) {
    throw new Error('Missing azure client id environment variables of pattern: AZURE_CLIENT_ID_[0-9]*');
  }

  return {
    azure: {
      clientIds: azureClientIds,
      tenantId: process.env.AZURE_TENANT_ID,
    },
    cognito: {
      clientIds: cognitoClientIds,
      poolId: process.env.COGNITO_POOL_ID,
      region: process.env.COGNITO_REGION,
    },
    configurationFile: {
      enabled: process.env.ENABLE_CONFIGURATION_FILE === 'true',
      filePath: process.env.CONFIGURATION_FILE_PATH,
    },
  };
};
