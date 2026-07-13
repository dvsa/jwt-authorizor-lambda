import { decode, Jwt } from 'jsonwebtoken';
import { Cognito } from './cognito';
import { Azure } from './azure';
import { Logger } from '../util/logger';

export class TokenVerifier {
  cognito: Cognito;

  azure: Azure;

  logger: Logger;

  constructor(cognito: Cognito, azure: Azure, logger: Logger) {
    this.cognito = cognito;
    this.azure = azure;
    this.logger = logger;
  }

  public async verify(rawToken: string): Promise<boolean> {
    try {
      const decodedToken = this.decode(rawToken);

      return await this.verifyToken(rawToken, decodedToken);
    } catch (err) {
      const { message } = err as Error;
      this.logger.info(message);
      return false;
    }
  }

  public async getVerifiedDecodedToken(rawToken: string): Promise<Jwt> {
    try {
      const decodedToken = this.decode(rawToken);

      if (await this.verifyToken(rawToken, decodedToken)) {
        return decodedToken;
      }

      return undefined;
    } catch (err) {
      const { message } = err as Error;
      this.logger.info(message);
      return undefined;
    }
  }

  private decode(token: string): Jwt {
    const decodedToken: Jwt = decode(token, { complete: true });
    if (!decodedToken) {
      throw new Error('Failed to decode provided JWT');
    }
    return decodedToken;
  }

  private async verifyToken(rawToken: string, decodedToken: Jwt): Promise<boolean> {
    if (typeof decodedToken.payload === 'string') {
      throw new Error('Unable to decode payload into object, instead received string.');
    }

    const { iss } = decodedToken.payload;

    if (iss === this.cognito.getIssuer()) {
      return this.cognito.verify(rawToken, decodedToken);
    }

    if (this.azure.getAzureIssuers().includes(iss)) {
      return this.azure.verify(rawToken, decodedToken);
    }

    throw new Error(`Token issuer '${iss}' not accepted`);
  }
}
