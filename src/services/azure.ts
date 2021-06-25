import axios from 'axios';
import * as jwt from 'jsonwebtoken';

export const verify = async (rawToken: string, decodedToken: any) => {
  const key: string = await getCertificateChain(decodedToken.header.kid);
  jwt.verify(rawToken, key, { audience: clientId });
  return true;
};

const baseUrl = 'https://login.microsoftonline.com';

let tenantId: string | undefined;
let clientId: string | undefined;

export const setCredentials = (azureTenantId: string, azureClientId: string) => {
  tenantId = azureTenantId;
  clientId = azureClientId;
};

const getCertificateChain = async (keyId: string): Promise<string> => {
  const keys: Map<string, string> = await getKeys();

  const certificateChain = keys.get(keyId);

  if (!certificateChain) {
    throw new Error(`no public key with ID '${keyId}' under tenant ${tenantId}`);
  }

  return certificateChain;
};

export const getIssuer = (): string => `${baseUrl}/${tenantId}/v2.0`;

const getKeys = async (): Promise<Map<string, string>> => {
  const response = await axios.get(`${baseUrl}/${tenantId}/discovery/keys`);

  const map: Map<string, string> = new Map();

  for (const key of response.data.keys) {
    const keyId = key.kid;
    const certificateChain = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;

    map.set(keyId, certificateChain);
  }

  return map;
};
