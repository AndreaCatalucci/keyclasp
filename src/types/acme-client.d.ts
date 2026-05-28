declare module "acme-client" {
  export class Client {
    constructor(opts: { directoryUrl: string; accountKey: any });
    createAccount(opts: { termsOfServiceAgreed: boolean; contact?: string[] }): Promise<any>;
    createOrder(opts: { identifiers: { type: string; value: string }[] }): Promise<any>;
    getAuthorizations(order: any): Promise<any[]>;
    getChallengeKeyAuthorization(challenge: any): Promise<string>;
    verifyChallenge(challenge: any): Promise<void>;
    completeChallenge(challenge: any): Promise<void>;
    waitForValidStatus(challenge: any): Promise<void>;
    finalizeOrder(order: any, csr: any): Promise<void>;
    getCertificate(order: any): Promise<{ certificate: string; key: string; chain?: string }>;
  }
  export enum Directory {
    LetsEncryptStaging = "letsencrypt-staging",
    LetsEncryptProduction = "letsencrypt-production",
  }
  export const Crypto: {
    createPrivateKey(): Promise<any>;
  };
}
