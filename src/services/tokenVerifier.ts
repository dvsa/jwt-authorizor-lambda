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

    switch (decodedToken.payload.iss) {
      case this.cognito.getIssuer():
        return this.cognito.verify(rawToken, decodedToken);
      case this.azure.getIssuer():
        return this.azure.verify(rawToken, decodedToken);
      default:
        throw new Error(`Token issuer '${decodedToken.payload.iss}' not accepted`);
    }
  }
}
