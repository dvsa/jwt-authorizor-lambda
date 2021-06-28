import { loadConfig, AuthorizerConfig } from '../../../src/services/configuration';

describe('Test configuration', () => {
  test('loadConfig() should throw error when cognito pool id env var missing', () => {
    expect(() => loadConfig()).toThrow(/cognito pool id/);
  });

  test('loadConfig() should throw error when cognito region env var missing', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    expect(() => loadConfig()).toThrow(/cognito region/);
  });

  test('loadConfig() should throw error when cognito client id env var missing', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    expect(() => loadConfig()).toThrow(/cognito client id/);
  });

  test('loadConfig() should throw error when azure tenant id env var missing', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.COGNITO_CLIENT_ID = 'cognito_client_id';
    expect(() => loadConfig()).toThrow(/azure tenant id/);
  });

  test('loadConfig() should throw error when azure client id env var missing', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    expect(() => loadConfig()).toThrow(/azure client id/);
  });

  test('loadConfig() should return config instance when env vars exist', () => {
    process.env.COGNITO_POOL_ID = 'cognito_pool_id';
    process.env.COGNITO_REGION = 'cognito_region';
    process.env.AZURE_TENANT_ID = 'azure_tenant_id';
    process.env.AZURE_CLIENT_ID = 'azure_client_id';

    const config: AuthorizerConfig = loadConfig();
    expect(config.cognito.poolId).toBe('cognito_pool_id');
    expect(config.cognito.region).toBe('cognito_region');
    expect(config.cognito.clientId).toBe('cognito_client_id');
    expect(config.azure.tenantId).toBe('azure_tenant_id');
    expect(config.azure.clientId).toBe('azure_client_id');
  });
});
