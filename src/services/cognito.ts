import axios, { AxiosResponse } from 'axios';
import jwkToPem from 'jwk-to-pem';
import * as jwt from 'jsonwebtoken';
import { Jwt } from '../types/types';
import { Logger } from '../util/logger';

export interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

export interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

export interface PublicKeys {
  keys: PublicKey[];
}

interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}

export class Cognito {
  region: string;

  poolId: string;

  clientId: string;

  cacheKeys: MapOfKidToPublicKey | undefined;

  logger: Logger;

  constructor(region: string, poolId: string, clientId: string, logger: Logger) {
    this.region = region;
    this.poolId = poolId;
    this.clientId = clientId;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken: Jwt): Promise<boolean> {
    try {
      const key: string = await this.getCertificateChain(decodedToken.header.kid);
      jwt.verify(rawToken, key);
    } catch (err) {
      this.logger.info(`Failed to verify jwt:: ${err.message}`);
      return false;
    }

    if (decodedToken.payload.client_id !== this.clientId) {
      this.logger.info("Failed to verify jwt:: contains invalid 'client_id'");
      return false;
    }

    if (decodedToken.payload.token_use !== 'access') {
      this.logger.info("Failed to verify jwt:: contains invalid 'token_use'");
      return false;
    }

    return true;
  }

  public getIssuer(): string {
    return `https://cognito-idp.${this.region}.amazonaws.com/${this.poolId}`;
  }

  public async getCertificateChain(keyId: string): Promise<string> {
    const keys: MapOfKidToPublicKey = await this.getKeys();
    const certificateChain = keys[keyId];

    if (!certificateChain) {
      throw new Error(`no public key with ID '${keyId}' under pool ${this.poolId}`);
    }

    return certificateChain.pem;
  }

  protected async getKeys(): Promise<MapOfKidToPublicKey> {
    if (this.cacheKeys) {
      return this.cacheKeys;
    }

    const url = `${this.getIssuer()}/.well-known/jwks.json`;
    const publicKeys = await axios.get<PublicKeys>(url);

    this.cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
      const pem = jwkToPem(current);
      agg[current.kid] = {
        instance: current,
        pem,
      };
      return agg;
    }, {} as MapOfKidToPublicKey);
    return this.cacheKeys;
  }
}
