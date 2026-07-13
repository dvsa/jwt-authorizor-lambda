import { verify, Jwt, JwtPayload } from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import { Logger } from '../util/logger';

export class Azure {
  tenantId: string;

  clientIds: string[];

  logger: Logger;

  baseUrlV1 = 'https://sts.windows.net';

  baseUrlV2 = 'https://login.microsoftonline.com';

  constructor(tenantId: string, clientIds: string[], logger: Logger) {
    this.tenantId = tenantId;
    this.clientIds = clientIds;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken: Jwt): Promise<boolean> {
    try {
      const decodedPayload = decodedToken.payload as JwtPayload;

      const issuer = decodedPayload.iss;

      const validIssuers = this.getAzureIssuers();

      if (!issuer || !validIssuers.includes(issuer)) {
        this.logger.info(`Failed to verify jwt:: invalid issuer ${issuer}`);
        return false;
      }

      const tokenAud = decodedPayload.aud;

      let audience: string | undefined;
      if (Array.isArray(tokenAud)) {
        audience = this.clientIds.find((clientId) => tokenAud.includes(clientId));
      } else if (typeof tokenAud === 'string') {
        audience = this.clientIds.find((clientId) => clientId === tokenAud);
      }

      if (!audience) {
        this.logger.info('Failed to verify jwt:: token contains invalid audience');
        return false;
      }

      const key: string = await this.getPublicKey(
        decodedToken.header.kid,
        issuer,
      );

      verify(rawToken, key, {
        audience,
        issuer: validIssuers,
      });

      return true;
    } catch (err) {
      const { message } = err as Error;
      this.logger.info(`Failed to verify jwt:: ${message}`);
      return false;
    }
  }

  public getAzureIssuers(): string[] {
    return [
      `${this.baseUrlV1}/${this.tenantId}/`, // Azure AD v1 endpoint (legacy issuer)
      `${this.baseUrlV2}/${this.tenantId}/v2.0`, // Microsoft identity platform v2 endpoint (modern)
    ];
  }

  protected async getPublicKey(
    keyId: string,
    issuer: string,
  ): Promise<string> {
    const isV2 = issuer.startsWith(this.baseUrlV2);

    const jwksUri = isV2
      ? `${this.baseUrlV2}/${this.tenantId}/discovery/v2.0/keys`
      : `${this.baseUrlV1}/${this.tenantId}/discovery/keys`;

    const jwksClient = JwksClient({
      jwksUri,
    });

    const key = await jwksClient.getSigningKey(keyId);
    return key.getPublicKey();
  }
}
