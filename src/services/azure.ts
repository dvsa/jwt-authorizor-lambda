import axios from 'axios';
import * as jwt from 'jsonwebtoken';
import { Logger } from "../util/logger";

export class Azure {
  tenantId: string;

  clientId: string;

  logger: Logger;

  baseUrl = 'https://login.microsoftonline.com';

  cacheKeys: Map<string, string> | undefined;

  constructor(tenantId: string, clientId: string, logger: Logger) {
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.logger = logger;
  }

  public async verify(rawToken: string, decodedToken): Promise<boolean> {
    try {
      const key: string = await this.getCertificateChain(decodedToken.header.kid);
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

  protected async getCertificateChain(keyId: string): Promise<string> {
    const keys: Map<string, string> = await this.getKeys();

    const certificateChain = keys.get(keyId);

    if (!certificateChain) {
      throw new Error(`no public key with ID '${keyId}' under tenant ${this.tenantId}`);
    }

    return certificateChain;
  }

  protected async getKeys(): Promise<Map<string, string>> {
    if (this.cacheKeys) {
      return this.cacheKeys;
    }

    const response = await axios.get(`${this.baseUrl}/${this.tenantId}/discovery/keys`);

    this.cacheKeys = new Map();

    for (const key of response.data.keys) {
      const keyId = key.kid;
      const certificateChain = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;

      this.cacheKeys.set(keyId, certificateChain);
    }

    return this.cacheKeys;
  }
}
