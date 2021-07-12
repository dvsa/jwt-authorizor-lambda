import { verify, Jwt } from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import { Logger } from '../util/logger';

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

  public async verify(rawToken: string, {
    header: { kid },
    payload: {
      client_id,
      token_use,
    },
  }: Jwt): Promise<boolean> {
    try {
      const key: string = await this.getPublicKey(kid);
      verify(rawToken, key);
    } catch (err) {
      const { message } = err as Error;
      this.logger.info(`Failed to verify jwt:: ${message}`);
      return false;
    }

    if (!this.clientIds.includes(<string>client_id)) {
      this.logger.info("Failed to verify jwt:: contains invalid 'client_id'");
      return false;
    }

    if (token_use !== 'access') {
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
