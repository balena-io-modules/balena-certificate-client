/*
Copyright 2018 Balena Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import * as Promise from 'bluebird';
import * as request from 'request-promise';

/**
 * Options passed to the DnsUpdateClient on construction.
 */
export interface DnsUpdateOptions {
	/** Host URI of the DNS service to be used. */
	host: string;
	/** Port number the DNS service should be listening on. */
	port: number;
	/** An authentication token to use for DNS upates. */
	authToken: string;
}

/**
 * Client to talk to the DNS service.
 */
export class DnsUpdateClient {
	private hostUrl: string;
	private authToken: string;

	constructor(constructOpts: DnsUpdateOptions) {
		// Verify this is a valid URL
		this.hostUrl = `${constructOpts.host}:${constructOpts.port}`;
		this.authToken = constructOpts.authToken;
	}

	// Create/update a TXT record
	public updateTxtRecord(domain: string, text: string): Promise<void> {
		// POST /txt/{subdomain}
		// Header: "Authorization: token"
		// body: { text }
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

	// This will remove the given TXT record (should it exist)
	public removeTxtRecord(domain: string, text: string): Promise<void> {
		// DELETE /txt/{domain}
		// Header: "Authorization: token"
		// body: { text }
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

	// Either create or update an existing A record
	public updateARecord(domain: string, ip: string): Promise<void> {
		// POST /a/{domain}
		// Header: "Authorization: token"
		// body: { ip }
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

	// Remove an A record. Ideally this should be called when a device is destroyed
	public removeARecord(domain: string, ip: string): Promise<void> {
		// DELETE /a/{domain}
		// Header: "Authorization: token"
		// body: { ip }
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
}
