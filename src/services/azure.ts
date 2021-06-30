import axios from 'axios';
import * as jwt from 'jsonwebtoken';

export class Azure {
  tenantId: string;

  clientId: string;

  baseUrl = 'https://login.microsoftonline.com';

  cacheKeys: Map<string, string> | undefined;

  constructor(tenantId: string, clientId: string) {
    this.tenantId = tenantId;
    this.clientId = clientId;
  }

  public async verify(rawToken: string, decodedToken): Promise<boolean> {
    const key: string = await this.getCertificateChain(decodedToken.header.kid);
    jwt.verify(rawToken, key, { audience: this.clientId });
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
