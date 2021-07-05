import * as jwt from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import { Logger } from '../util/logger';

export class Azure {
  tenantId: string;

  clientId: string;

  logger: Logger;

  baseUrl = 'https://login.microsoftonline.com';

  constructor(tenantId: string, clientId: string, logger: Logger) {
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken): Promise<boolean> {
    try {
      const key: string = await this.getPublicKey(decodedToken.header.kid);
      jwt.verify(rawToken, key, { audience: this.clientId });
    } catch (err) {
      this.logger.info(`Failed to verify jwt:: ${err.message}`);
      return false;
    }
    return true;
  }

  public getIssuer(): string {
    return `${this.baseUrl}/${this.tenantId}/v2.0`;
  }

  protected async getPublicKey(keyId: string): Promise<string> {
    const jwksClient = JwksClient({
      jwksUri: `${this.baseUrl}/${this.tenantId}/discovery/keys`,
    });
    const key = await jwksClient.getSigningKey(keyId);

    return key.getPublicKey();
  }
}
