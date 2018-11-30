import * as Promise from 'bluebird';
export interface DnsUpdateOptions {
    host: string;
    port: number;
    authToken: string;
}
export declare class DnsUpdateClient {
    private hostUrl;
    private authToken;
    constructor(constructOpts: DnsUpdateOptions);
    updateTxtRecord(domain: string, text: string): Promise<void>;
    removeTxtRecord(domain: string, text: string): Promise<void>;
    updateARecord(domain: string, ip: string): Promise<void>;
    removeARecord(domain: string, ip: string): Promise<void>;
}
