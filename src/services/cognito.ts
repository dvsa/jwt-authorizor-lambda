import axios, { AxiosResponse } from 'axios';
import jwkToPem from 'jwk-to-pem';
import * as jwt from 'jsonwebtoken';

let cacheKeys: MapOfKidToPublicKey | undefined;
let region: string | undefined;
let poolId: string | undefined;
let clientId: string | undefined;

export const setCredentials = (cognitoRegion: string, cognitoPoolId: string, cognitoClientId: string): void => {
  region = cognitoRegion;
  poolId = cognitoPoolId;
  clientId = cognitoClientId;
};

export const verify = async (rawToken: string, decodedToken): Promise<boolean> => {
  const key: string = await getCertificateChain(decodedToken.header.kid);

  jwt.verify(rawToken, key);

  if (decodedToken.payload.client_id !== clientId) {
    return false;
  }

  if (decodedToken.payload.token_use !== 'access') {
    return false;
  }

  return false;
};

export const getIssuer = (): string => `https://cognito-idp.${region}.amazonaws.com/${poolId}`;

const getCertificateChain = async (keyId: string): Promise<string> => {
  const keys: MapOfKidToPublicKey = await getKeys();
  const certificateChain = keys[keyId];

  if (!certificateChain) {
    throw new Error(`no public key with ID '${keyId}' under pool ${poolId}`);
  }

  return certificateChain.pem;
};

const getKeys = async (): Promise<MapOfKidToPublicKey> => {
  if (cacheKeys) {
    return cacheKeys;
  }

  const url = `${getIssuer()}/.well-known/jwks.json`;
  const publicKeys = await axios.get<PublicKeys>(url);
  cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
    const pem = jwkToPem(current);
    agg[current.kid] = {
      instance: current,
      pem
    };
    return agg;
  }, {} as MapOfKidToPublicKey);
  return cacheKeys;
};

interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

interface PublicKeys {
  keys: PublicKey[];
}

interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}
