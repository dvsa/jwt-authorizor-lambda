import axios from 'axios';
import jwkToPem from 'jwk-to-pem';

let cacheKeys: MapOfKidToPublicKey | undefined;

export const getCertificateChain = async (region: string, poolId: string, keyId: string): Promise<string> => {
  const keys: MapOfKidToPublicKey = await getKeys(region, poolId);
  const certificateChain = keys[keyId];

  if (!certificateChain) {
    throw new Error(`no public key with ID '${keyId}' under pool ${poolId}`);
  }

  return certificateChain.pem;
};

const getKeys = async (region: string, poolId: string): Promise<MapOfKidToPublicKey> => {
  if (cacheKeys) {
    return cacheKeys;
  }

  const cognitoIssuer = `https://cognito-idp.${region}.amazonaws.com/${poolId}`;

  const url = `${cognitoIssuer}/.well-known/jwks.json`;
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

export interface PublicKey {
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

export interface PublicKeys {
  keys: PublicKey[];
}

export interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}
