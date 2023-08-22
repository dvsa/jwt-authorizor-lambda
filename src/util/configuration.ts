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

  if (process.env.ENABLE_CONFIGURATION_FILE === 'true' && !process.env.CONFIGURATION_FILE_PATH) {
    throw new Error('CONFIGURATION_FILE_PATH must be set when ENABLE_CONFIGURATION_FILE is true');
  }

  const cognitoClientIds: string[] = [];

  Object.keys(process.env).forEach((key) => {
    // allow up to 9999 cognito client ids
    const regex = /COGNITO_CLIENT_ID(_[0-9]{,4})?/g;
    if (key.match(regex)) {
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
    configurationFile: {
      enabled: process.env.ENABLE_CONFIGURATION_FILE === 'true',
      filePath: process.env.CONFIGURATION_FILE_PATH,
    },
  };
};
