import { loadConfig } from '../../src/util/configuration';

describe('Test configuration', () => {
  beforeEach(() => {
    delete process.env.COGNITO_POOL_ID;
    delete process.env.COGNITO_CLIENT_ID;
    delete process.env.COGNITO_CLIENT_ID_1;
    delete process.env.COGNITO_CLIENT_ID_2;
    delete process.env.COGNITO_POOL_ID;
    delete process.env.COGNITO_REGION;
    delete process.env.AZURE_TENANT_ID;
    delete process.env.AZURE_CLIENT_ID;
    delete process.env.ENABLE_CONFIGURATION_FILE;
    delete process.env.CONFIGURATION_FILE_PATH;
  });

  test('loadConfig() should throw error when cognito pool id env var missing', () => {
    expect(() => loadConfig()).toThrow(/COGNITO_POOL_ID/);
  });

  test('loadConfig() should throw error when cognito region env var missing', () => {
    expect(() => loadConfig()).toThrow(/COGNITO_REGION/);
  });

  test('loadConfig() should throw error when azure tenant id env var missing', () => {
    expect(() => loadConfig()).toThrow(/AZURE_TENANT_ID/);
  });

  test('loadConfig() should throw error when azure client id env var missing', () => {
    expect(() => loadConfig()).toThrow(/AZURE_CLIENT_ID/);
  });

  test('loadConfig() should throw error when enable configuration file env var is true but file path env var is missing', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    process.env.ENABLE_CONFIGURATION_FILE = 'true';

    expect(() => loadConfig()).toThrow(/CONFIGURATION_FILE_PATH must be set when ENABLE_CONFIGURATION_FILE is true/);
  });

  test('loadConfig() should throw an error when no cognito client id env vars have been set', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    expect(() => loadConfig()).toThrow('');
  });

  test('loadConfig() should handle single cognito client id', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';
    process.env.COGNITO_CLIENT_ID = 'cognito_client_id';

    const config = loadConfig();
    expect(config.cognito.clientIds).toEqual(['cognito_client_id']);
  });

  test('loadConfig() should return config instance when env vars exist', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_CLIENT_ID_1 = 'cognito_client_id_1';
    process.env.COGNITO_CLIENT_ID_2 = 'cognito_client_id_2';
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';
    process.env.ENABLE_CONFIGURATION_FILE = 'true';
    process.env.CONFIGURATION_FILE_PATH = '/path/to/config/file';

    const config = loadConfig();
    expect(config.cognito.poolId).toBe('cognito_pool_id');
    expect(config.cognito.region).toBe('cognito_region');
    expect(config.cognito.clientIds).toEqual(['cognito_client_id_1', 'cognito_client_id_2']);
    expect(config.azure.tenantId).toBe('azure_tenant_id');
    expect(config.azure.clientId).toBe('azure_client_id');
    expect(config.configurationFile.enabled).toBe(true);
    expect(config.configurationFile.filePath).toBe('/path/to/config/file');
  });

  test('loadConfig() should set configurationFile enabled to false when enable config file env var is not set', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_CLIENT_ID_1 = 'cognito_client_id_1';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    const config = loadConfig();
    expect(config.configurationFile.enabled).toBe(false);
  });

  test('loadConfig() should set configurationFile enabled to false when enable config file env var is not set to true', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_CLIENT_ID_1 = 'cognito_client_id_1';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    process.env.ENABLE_CONFIGURATION_FILE = 'something_other_than_true';

    const config = loadConfig();
    expect(config.configurationFile.enabled).toBe(false);
  });
});
