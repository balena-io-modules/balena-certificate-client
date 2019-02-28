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
import * as Bluebird from 'bluebird';
import * as Greenlock from 'greenlock';
import LEStore = require('le-store-certbot');
import * as _ from 'lodash';
import mkdirp = require('mkdirp-promise');
import * as mzfs from 'mz/fs';
import { TypedError } from 'typed-error';

import { DnsUpdateClient } from './dns-update-client';

/**
 * Constructor options for the BalenaCertificateClient class.
 */
export interface CertificateClientOptions {
	/** Host where the DNS update service is located */
	dnsUpdateHost: string;
	/** Port the DNS update service is running on */
	dnsUpdatePort: number;
	/** Authorisation token used for DNS updates */
	authToken: string;
	/** Directory where the LetsEncrypt config for the session will be saved */
	configRoot: string;
}

/**
 * Object used to pass details for the certificate to generate and IP to add DNS record for.
 */
export interface CertificateRequestOptions {
	/** Domain required, eg. `somedomain.io` */
	domain: string;
	/** Subdomains required, eg `*.1234567890abcdef`, `*.devices.1234567890abcdef`, `myserver`... */
	subdomains: string[];
	/** IP for local subnet location of device */
	ip: string;
	/**
	 * Root location where both LetsEncrypt `config` directory and `certificates`
	 * directory will be saved. If not passed, initially constructor args are
	 * used
	 */
	outputLocation?: string;
	/**
	 * This *must* be false if we're not within renewal period for a certificate,
	 * else true. This ensures if a valid certificate already exists, we do not
	 * attempt to renew too early (or create a new cert).
	 */
	renewing: boolean;
	/** Email address of owner of device (x@somedomainio) */
	email: string;
}
/**
 * Error codes denoting the type of error returned.
 */
export const enum CertificateClientErrorCodes {
	INVALID_TOKEN,
	MISSING_CONFIG,
	EXISTING_DOMAIN_CHALLENGE,
	MISSING_DOMAIN_CHALLENGE,
	EXISTING_CERTIFICATE,
	INVALID_RESPONSE,
	SERVICE_ERROR,
}

/**
 * The CertificateClientClass class returns appropriate errors that may occur internally in the
 * backend DNS service.
 */
export class CertificateClientError extends TypedError {
	public code: number;

	constructor(code: number, message: string) {
		super();

		this.code = code;
		this.message = message;
	}
}

/**
 * Returned by the requestCertificate when a certificate has successfully been generated
 * and the DNS entry updated.
 */
export interface CertificateResult {
	ca: string;
	privateKey: string;
	certificate: string;
}

/**
 * Certificate generation and DNS update client.
 */
export class BalenaCertificateClient {
	private greenlock: Greenlock.GreenlockInstance;
	private dnsClient: DnsUpdateClient;
	private configDirectory: string;
	private challengeMap = new Map<string, string>();

	// The dnsUpdateServer is the hostname where the Balena Registration DNS Update Service
	// is running, The dnsUpdatePort is the port it's running on
	constructor(constructOpts: CertificateClientOptions) {
		if (
			!constructOpts.dnsUpdateHost ||
			!constructOpts.dnsUpdatePort ||
			!constructOpts.authToken ||
			!constructOpts.configRoot
		) {
			throw new CertificateClientError(
				CertificateClientErrorCodes.MISSING_CONFIG,
				'A DNS service host, port, authentication token and config root must be specified',
			);
		}

		// Create a new DNS service client
		this.dnsClient = new DnsUpdateClient({
			host: constructOpts.dnsUpdateHost,
			port: constructOpts.dnsUpdatePort,
			authToken: constructOpts.authToken,
		});
		this.configDirectory = constructOpts.configRoot;

		// Create a Greenlock instance, including an LE store at the specified
		// root
		this.greenlock = Greenlock.create({
			version: 'draft-12',
			// The below is the Staging environment for LE, which can be used
			// for development testing.
			//server: 'https://acme-staging-v02.api.letsencrypt.org/directory',
			// The production LE service:
			server: 'https://acme-v02.api.letsencrypt.org/directory',
			store: LEStore.create({
				configDir: this.configDirectory,
			}),
			challenges: {
				'dns-01': this.dnsChallenge(),
			},
			// Renew within 14 days of expiry
			renewWithin: 14 * 24 * 60 * 60 * 1000,
			// Renewal should happen 10 days before expiry
			renewBy: 10 * 24 * 60 * 60 * 1000,
		});
	}

	// For brevity, we're returning a full challenge object
	private dnsChallenge(options?: Greenlock.CreateOptions): Greenlock.Challenge {
		return {
			getOptions: () => {
				return options || {};
			},

			set: (_args, domain, _challenge, keyAuthorization, callback) => {
				const txtDomain = `_acme-challenge.${domain}`;
				var keyAuthDigest = require('crypto')
					.createHash('sha256')
					.update(keyAuthorization || '')
					.digest('base64')
					.replace(/\+/g, '-')
					.replace(/\//g, '_')
					.replace(/=+$/g, '');

				// Add this to the challenge map, so we can remove it later
				// If there's already an entry, we do not honour this and throw an error
				Bluebird.try(() => {
					if (this.challengeMap.has(txtDomain)) {
						throw new CertificateClientError(
							CertificateClientErrorCodes.EXISTING_CERTIFICATE,
							'A challenge for a certificate already exists',
						);
					}
					this.challengeMap.set(txtDomain, keyAuthDigest);

					// Once the call returns, we'll be ready for the challenge to be tested
					return this.dnsClient.updateTxtRecord(txtDomain, keyAuthDigest);
				}).asCallback(callback);
			},

			get: (_defaults, _domain, _challenge, callback) => {
				// We don't do anything.
				callback(null);
			},

			remove: (_args, domain, _challenge, callback) => {
				const txtDomain = `_acme-challenge.${domain}`;

				// Retrieve the appropriate text from the challenge map
				Bluebird.try(() => {
					const keyAuthDigest = this.challengeMap.get(txtDomain);
					if (!keyAuthDigest) {
						throw new CertificateClientError(
							CertificateClientErrorCodes.MISSING_DOMAIN_CHALLENGE,
							'The challenge text for a domain is missing from the challenge map',
						);
					}

					// Once the call returns, the record has been removed
					return this.dnsClient.removeTxtRecord(txtDomain, keyAuthDigest);
				}).asCallback(callback);
			},
		};
	}

	// Make a request for a valid certificate for the UUID specified, using the IP and
	// email details given, ensuring results are saved to the resultLocation
	// This will:
	// 1. Request a new certificate from LetsEncrypt
	// 2. Add a new A record for `*.<uuid>.ba.io` and `*.devices.<uuid>.resindev.io`
	// Or fail
	// On return, the resultLocation will include the certificate chains returned from
	// LetsEncrypt, and a new A record will be globally available for the UUID
	public async requestCertificate(
		certRequest: CertificateRequestOptions,
	): Promise<CertificateResult | null> {
		const greenlockInst = this.greenlock;
		const outDir = certRequest.outputLocation;
		const domain = certRequest.domain;
		const subdomains = certRequest.subdomains;
		const requestDomains = !subdomains
			? [domain]
			: _.reduce(
					subdomains,
					(result, value) => {
						result.push(`${value}.${domain}`);
						return result;
					},
					[''],
			  ).slice(1);
		let certificates: CertificateResult | null = null;
		let certsExist: Greenlock.CertificateResults;

		try {
			certsExist = await greenlockInst.check({ domains: requestDomains });
			if (!certsExist) {
				const results = await greenlockInst.register({
					domains: requestDomains,
					email: certRequest.email,
					agreeTos: true,
					rsaKeySize: 2048,
					challengeType: 'dns-01',
				});

				certificates = {
					ca: results.chain,
					privateKey: results.privkey,
					certificate: results.cert,
				};

				// The certificates will be stored along with the config in the
				// chosen directory. However, it's possible we've been given
				// a location to store the key, eec and CA, so if so we'll
				// save them there, too.
				// We only store:
				//  * Private key
				//  * CA
				//  * EEC
				if (outDir) {
					const outFiles = [
						{ file: `${outDir}/ca.pem`, data: certificates.ca },
						{
							file: `${outDir}/private-key.pem`,
							data: certificates.privateKey,
						},
						{
							file: `${outDir}/certificate.pem`,
							data: certificates.certificate,
						},
					];

					await mkdirp(outDir);
					await Bluebird.map(outFiles, async entry => {
						await mzfs.writeFile(entry.file, entry.data);
					});
				}
			}

			// If the current domains we want match those retrieved *and* the IP
			// address is the same, we don't carry out the expensive update request
			// Test the IPs and filter the requests down to only those domains whose
			// IP addresses do not match.
			const records = await this.dnsClient.retrieveARecords(domain);
			const finalDomains = _.filter(requestDomains, domain => {
				const matchingDomain = _.find(
					records,
					record => record.domain === domain,
				);
				return matchingDomain ? !(matchingDomain.ip === certRequest.ip) : true;
			});

			// Regardless of whether certs were generated or not, create/update a DNS A
			// record with the given IP
			await Bluebird.map(finalDomains, async newDomain => {
				await this.dnsClient.updateARecord(newDomain, certRequest.ip);
			});
		} catch (error) {
			// If the returned error is about tokens, we use that.
			if (
				_.includes(
					error.message,
					'A valid bearer token must be included in the request',
				)
			) {
				throw new CertificateClientError(
					CertificateClientErrorCodes.INVALID_TOKEN,
					'The passed bearer token was invalid',
				);
			}
			throw error;
		}

		// If certifcates already existed, we throw an error.
		if (certsExist) {
			throw new CertificateClientError(
				CertificateClientErrorCodes.EXISTING_CERTIFICATE,
				'A certificate already exists for the requested domain',
			);
		}

		return certificates;
	}
}
