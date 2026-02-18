export interface Configuration {
  cognito: CognitoConfig
  azure: AzureConfig
  configurationFile: ConfigurationFileConfig
}

export interface CognitoConfig {
  poolId: string
  region: string
  clientIds: string[]
}

export interface AzureConfig {
  tenantId: string
  clientIds: string[]
}

export interface ConfigurationFileConfig {
  enabled: boolean
  filePath: string
}

export interface RoleConfig {
  role: string
  authorisedEndpoints: AuthorisedEndpoint[]
}

export interface AuthorisedEndpoint {
  httpVerb: string
  url: string
}

export type PermissionsConfig = Array<RoleConfig>;
