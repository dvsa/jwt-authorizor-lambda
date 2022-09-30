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

  public decode(token: string): Jwt {
    const decodedToken: Jwt = decode(token, { complete: true });
    if (!decodedToken) {
      throw new Error('Failed to decode provided JWT');
    }
    return decodedToken;
  }

  public async verify(rawToken: string):Promise<boolean> {
    try {
      const decodedToken = this.decode(rawToken);

      if (typeof decodedToken.payload === 'string') {
        throw new Error('Unable to decode payload into object, instead received string.');
      }

      switch (decodedToken.payload.iss) {
        case this.cognito.getIssuer():
          return await this.cognito.verify(rawToken, decodedToken);
        case this.azure.getIssuer():
          return await this.azure.verify(rawToken, decodedToken);
        default:
          throw new Error(`Token issuer '${decodedToken.payload.iss}' not accepted`);
      }
    } catch (err) {
      const { message } = err as Error;
      this.logger.info(message);
      return false;
    }
  }
}
