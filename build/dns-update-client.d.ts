import * as Bluebird from 'bluebird';
export interface DnsUpdateOptions {
    host: string;
    port: number;
    authToken: string;
}
export interface DnsARecord {
    domain: string;
    ip: string;
}
export declare class DnsUpdateClient {
    private hostUrl;
    private authToken;
    constructor(constructOpts: DnsUpdateOptions);
    updateTxtRecord(domain: string, text: string): Bluebird<void>;
    removeTxtRecord(domain: string, text: string): Bluebird<void>;
    updateARecord(domain: string, ip: string): Bluebird<void>;
    removeARecord(domain: string, ip: string): Bluebird<void>;
    retrieveARecords(domain: string): Bluebird<DnsARecord[]>;
}
