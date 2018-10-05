/*
Copyright 2018 Resinio Ltd

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
import * as Greenlock from 'greenlock';
import LEStore = require('le-store-certbot');
import * as _ from 'lodash';
import mkdirp = require('mkdirp-promise');
import * as mzfs from 'mz/fs';
import { TypedError } from 'typed-error';

import { DnsUpdateClient } from './dnsUpdateClient';

/**
 * Constructor options for the BalenaDevenvCertificateClient class.
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
	/** UUID for Devenv instance */
	uuid: string;
	/** Domain required, eg. `somedomain.io` */
	domain: string;
	/** IP for local subnet location of Devenv */
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
	/**Email address of owner of Devenv (x@somedomainio) */
	email: string;
}
/**
 * Error codes denoting the type of error returned.
 */
export enum CertificateClientErrorCodes {
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
interface CertificateResult {
	ca: string;
	privateKey: string;
	certificate: string;
}

/**
 * Certificate generation and DNS update client.
 */
export class BalenaDevenvCertificateClient {
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
			//server: 'https://acme-staging.api.letsencrypt.org/directory',
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
	private dnsChallenge(options?: any) {
		return {
			getOptions: () => {
				return options || {};
			},

			set: (
				_args: any,
				domain: any,
				_challenge: any,
				keyAuthorization: any,
				callback: (opt: any | null) => any,
			) => {
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
				if (this.challengeMap.has(txtDomain)) {
					callback(
						new CertificateClientError(
							CertificateClientErrorCodes.EXISTING_CERTIFICATE,
							'A challenge for a certificate already exists',
						),
					);
					return;
				}
				this.challengeMap.set(txtDomain, keyAuthDigest);

				// Once the call returns, we'll be ready for the challenge to be tested
				this.dnsClient
					.updateTxtRecord(txtDomain, keyAuthDigest)
					.asCallback(callback);
			},

			get: (
				_defaults: any,
				_domain: any,
				_challenge: any,
				callback: (opt: any | null) => void,
			) => {
				// We don't do anything.
				callback(null);
			},

			remove: (
				_args: any,
				domain: any,
				_challenge: any,
				callback: (opt: any | null) => void,
			) => {
				const txtDomain = `_acme-challenge.${domain}`;

				// Retrieve the appropriate text from the challenge map
				const keyAuthDigest = this.challengeMap.get(txtDomain);
				if (!keyAuthDigest) {
					callback(
						new CertificateClientError(
							CertificateClientErrorCodes.MISSING_DOMAIN_CHALLENGE,
							'The challenge text for a domain is missing from the challenge map',
						),
					);
					return;
				}

				// Once the call returns, the record has been removed
				this.dnsClient
					.removeTxtRecord(txtDomain, keyAuthDigest)
					.asCallback(callback);
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
	public requestCertificate(
		certRequest: CertificateRequestOptions,
	): Promise<CertificateResult> {
		const greenlockInst = this.greenlock;
		const outDir = certRequest.outputLocation;
		const requestDomains = [
			`*.${certRequest.uuid}.${certRequest.domain}`,
			`*.devices.${certRequest.uuid}.${certRequest.domain}`,
		];
		let certificates: CertificateResult;

		return greenlockInst
			.check({ domains: requestDomains })
			.then(function(results) {
				// We already have certificates here, but we don't know if they're about to
				// expire. We should ideally pass a flag.
				if (results) {
					if (!certRequest.renewing) {
						throw new CertificateClientError(
							CertificateClientErrorCodes.EXISTING_CERTIFICATE,
							'A certificate already exists for the requested domain',
						);
					}
				}

				// Attempt to grab new certificate
				return greenlockInst
					.register({
						domains: requestDomains,
						email: certRequest.email,
						agreeTos: true,
						rsaKeySize: 2048,
						challengeType: 'dns-01',
					})
					.then((results: Greenlock.CertificateResults) => {
						certificates = {
							ca: results.chain,
							privateKey: results.privkey,
							certificate: results.cert,
						};
						let resultPromise = Promise.resolve();

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
									file: `${outDir}/privateKey.pem`,
									data: certificates.privateKey,
								},
								{
									file: `${outDir}/certificate.pem`,
									data: certificates.certificate,
								},
							];

							resultPromise = mkdirp(outDir).then(() => {
								return Promise.map(outFiles, entry => {
									return mzfs.writeFile(entry.file, entry.data);
								}).then(() => {
									return;
								});
							});
						}

						return resultPromise;
					});
			})
			.then(() => {
				// Create/Update a DNS A record with the given IP
				return Promise.map(requestDomains, domain => {
					return this.dnsClient.updateARecord(domain, certRequest.ip);
				});
			})
			.then(() => {
				return certificates;
			})
			.catch((error: Error) => {
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
			});
	}
}
