"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const request = require("request-promise");
class DnsUpdateClient {
    constructor(constructOpts) {
        this.hostUrl = `${constructOpts.host}:${constructOpts.port}`;
        this.authToken = constructOpts.authToken;
    }
    updateTxtRecord(domain, text) {
        return request({
            uri: `${this.hostUrl}/txt/${domain}`,
            json: true,
            method: 'POST',
            headers: {
                Authorization: this.authToken,
            },
            body: {
                text,
            },
        }).promise();
    }
    removeTxtRecord(domain, text) {
        return request({
            uri: `${this.hostUrl}/txt/${domain}`,
            json: true,
            method: 'DELETE',
            headers: {
                Authorization: this.authToken,
            },
            body: {
                text,
            },
        }).promise();
    }
    updateARecord(domain, ip) {
        return request({
            uri: `${this.hostUrl}/a/${domain}`,
            json: true,
            method: 'POST',
            headers: {
                Authorization: this.authToken,
            },
            body: {
                ip,
            },
        }).promise();
    }
    removeARecord(domain, ip) {
        return request({
            uri: `${this.hostUrl}/a/${domain}`,
            json: true,
            method: 'DELETE',
            headers: {
                Authorization: this.authToken,
            },
            body: {
                ip,
            },
        }).promise();
    }
    retrieveARecords(domain) {
        return request({
            uri: `${this.hostUrl}/a/${domain}`,
            json: true,
            method: 'GET',
            headers: {
                Authorization: this.authToken,
            },
        }).promise();
    }
}
exports.DnsUpdateClient = DnsUpdateClient;
//# sourceMappingURL=dns-update-client.js.map