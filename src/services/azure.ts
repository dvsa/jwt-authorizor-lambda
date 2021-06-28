import axios from 'axios';
import * as jwt from 'jsonwebtoken';

const baseUrl = 'https://login.microsoftonline.com';

let cacheKeys: Map<string, string> | undefined;
let tenantId: string | undefined;
let clientId: string | undefined;

export const setCredentials = (azureTenantId: string, azureClientId: string) => {
  tenantId = azureTenantId;
  clientId = azureClientId;
};

export const verify = async (rawToken: string, decodedToken: any) => {
  const key: string = await getCertificateChain(decodedToken.header.kid);
  jwt.verify(rawToken, key, { audience: clientId });
  return true;
};

export const getIssuer = (): string => `${baseUrl}/${tenantId}/v2.0`;

const getCertificateChain = async (keyId: string): Promise<string> => {
  const keys: Map<string, string> = await getKeys();

  const certificateChain = keys.get(keyId);

  if (!certificateChain) {
    throw new Error(`no public key with ID '${keyId}' under tenant ${tenantId}`);
  }

  return certificateChain;
};

const getKeys = async (): Promise<Map<string, string>> => {
  if (cacheKeys) {
    return cacheKeys;
  }

  const response = await axios.get(`${baseUrl}/${tenantId}/discovery/keys`);
  cacheKeys = new Map();

  for (const key of response.data.keys) {
    const keyId = key.kid;
    const certificateChain = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;

    cacheKeys.set(keyId, certificateChain);
  }

  return cacheKeys;
};
