import * as jwt from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import { Logger } from '../util/logger';
import { Jwt } from '../types/jwt';

export class Cognito {
  region: string;

  poolId: string;

  clientIds: string[];

  logger: Logger;

  constructor(region: string, poolId: string, clientIds: string[], logger: Logger) {
    this.region = region;
    this.poolId = poolId;
    this.clientIds = clientIds;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken: Jwt): Promise<boolean> {
    try {
      const key: string = await this.getPublicKey(decodedToken.header.kid);
      jwt.verify(rawToken, key);
    } catch (err) {
      this.logger.info(`Failed to verify jwt:: ${err.message}`);
      return false;
    }

    if (!this.clientIds.includes(<string>decodedToken.payload.client_id)) {
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

  public async getPublicKey(keyId: string): Promise<string> {
    const jwksClient = JwksClient({
      jwksUri: `${this.getIssuer()}/.well-known/jwks.json`,
    });
    const key = await jwksClient.getSigningKey(keyId);

    return key.getPublicKey();
  }
}
