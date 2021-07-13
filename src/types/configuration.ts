export interface Configuration {
  cognito: CognitoConfig
  azure: AzureConfig
}

export interface CognitoConfig {
  poolId: string,
  region: string,
  clientIds: string[]
}

export interface AzureConfig {
  tenantId: string,
  clientId: string
}
