import * as Promise from 'bluebird';
import { TypedError } from 'typed-error';
export interface CertificateClientOptions {
    dnsUpdateHost: string;
    dnsUpdatePort: number;
    authToken: string;
    configRoot: string;
}
export interface CertificateRequestOptions {
    domain: string;
    subdomains: string[];
    ip: string;
    outputLocation?: string;
    renewing: boolean;
    email: string;
}
export declare const enum CertificateClientErrorCodes {
    INVALID_TOKEN = 0,
    MISSING_CONFIG = 1,
    EXISTING_DOMAIN_CHALLENGE = 2,
    MISSING_DOMAIN_CHALLENGE = 3,
    EXISTING_CERTIFICATE = 4,
    INVALID_RESPONSE = 5,
    SERVICE_ERROR = 6
}
export declare class CertificateClientError extends TypedError {
    code: number;
    constructor(code: number, message: string);
}
export interface CertificateResult {
    ca: string;
    privateKey: string;
    certificate: string;
}
export declare class BalenaCertificateClient {
    private greenlock;
    private dnsClient;
    private configDirectory;
    private challengeMap;
    constructor(constructOpts: CertificateClientOptions);
    private dnsChallenge;
    requestCertificate(certRequest: CertificateRequestOptions): Promise<CertificateResult | null>;
}
