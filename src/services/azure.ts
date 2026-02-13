import { verify, Jwt, JwtPayload } from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import { Logger } from '../util/logger';

export class Azure {
  tenantId: string;

  clientIds: string[];

  logger: Logger;

  baseUrl = 'https://sts.windows.net';

  constructor(tenantId: string, clientIds: string[], logger: Logger) {
    this.tenantId = tenantId;
    this.clientIds = clientIds;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken: Jwt): Promise<boolean> {
    try {
      const decodedPayload = decodedToken.payload as JwtPayload & { aud: string };
      const audience = this.clientIds.find((clientId) => clientId === decodedPayload.aud);

      if (!audience) {
        this.logger.info('Failed to verify jwt:: token contains invalid audience');
        return false;
      }

      const key: string = await this.getPublicKey(decodedToken.header.kid);
      verify(rawToken, key, { audience });
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
