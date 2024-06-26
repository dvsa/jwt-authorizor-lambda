import { verify, Jwt } from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import { Logger } from '../util/logger';

export class Azure {
  tenantId: string;

  clientId: string;

  logger: Logger;

  baseUrl = 'https://sts.windows.net';

  constructor(tenantId: string, clientId: string, logger: Logger) {
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken: Jwt): Promise<boolean> {
    try {
      const key: string = await this.getPublicKey(decodedToken.header.kid);
      verify(rawToken, key, { audience: this.clientId });
    } catch (err) {
      const { message } = err as Error;
      this.logger.info(`Failed to verify jwt:: ${message}`);
      return false;
    }
    return true;
  }

  public getIssuer(): string {
    return `${this.baseUrl}/${this.tenantId}/`;
  }

  protected async getPublicKey(keyId: string): Promise<string> {
    const jwksClient = JwksClient({
      jwksUri: `${this.baseUrl}/${this.tenantId}/discovery/keys`,
    });
    const key = await jwksClient.getSigningKey(keyId);

    return key.getPublicKey();
  }
}
