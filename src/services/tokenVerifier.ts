import * as jwt from 'jsonwebtoken';
import { Cognito } from './cognito';
import { Azure } from './azure';
import { Logger } from '../util/logger';
import { Jwt } from '../types/types';

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
    const decodedToken: Jwt = jwt.decode(token, { complete: true }) as Jwt;
    if (!decodedToken) {
      throw new Error('Failed to decode provided JWT');
    }
    return decodedToken;
  }

  public async verify(rawToken: string) {
    try {
      const decodedToken = this.decode(rawToken);
      let result;
      switch (decodedToken.payload.iss) {
        case this.cognito.getIssuer():
          return await this.cognito.verify(rawToken, decodedToken);
          break;
        case this.azure.getIssuer():
          return await this.azure.verify(rawToken, decodedToken);
          break;
        default:
          throw new Error(`Token issuer '${decodedToken.payload.iss}' not accepted`);
      }
    } catch (err) {
      this.logger.info(err.message);
      return false;
    }
  }
}
