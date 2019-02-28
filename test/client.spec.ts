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
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as DNS from 'dns';
import * as _ from 'lodash';
import 'mocha';
import * as rimraf from 'rimraf';

import {
	BalenaCertificateClient,
	CertificateClientError,
	CertificateClientErrorCodes,
} from '../src/client';
import { DnsUpdateClient } from '../src/dns-update-client';

// Include Chai and ensure that `should` is defined
chai.use(chaiAsPromised);
const { should } = chai.should();
should.exist;

const dnsHost = process.env.CERT_TEST_HOST || '';
const dnsPort = parseInt(process.env.CERT_TEST_PORT || '0', 10);
const domain = process.env.CERT_TEST_DOMAIN || '';
const email = process.env.CERT_TEST_EMAIL || '';
const authToken = process.env.CERT_TEST_AUTH_TOKEN || '';

// Utility function for removing certificate directories
function removeDirectory(dir: string): Bluebird<void> {
	return Bluebird.fromCallback((cb: (err: Error, result?: any) => void) => {
		rimraf(dir, cb);
	});
}

describe('Certificate Client', () => {
	const uuid = '1234567890';
	const dnsClient = new DnsUpdateClient({
		host: dnsHost,
		port: dnsPort,
		authToken,
	});

	// We should fail if the host or the authentication token is invalid
	describe('Invalid config/authorisation details', () => {
		const configRoot = `${process.cwd()}/test/invalidtoken`;

		// Ensure cert directory is cleaned up post-test
		after(() => {
			return removeDirectory(configRoot);
		});

		it('should fail for bad DNS service host details', () => {
			try {
				new BalenaCertificateClient({
					dnsUpdateHost: '',
					dnsUpdatePort: 0,
					authToken: '1234',
					configRoot: `${process.cwd()}/test/invalidtoken`,
				});
			} catch (error) {
				error.code.should.equal(CertificateClientErrorCodes.MISSING_CONFIG);
			}
		});

		it('should fail if auth token is invalid', () => {
			const client = new BalenaCertificateClient({
				dnsUpdateHost: dnsHost,
				dnsUpdatePort: dnsPort,
				authToken: '1234',
				configRoot,
			});

			return client
				.requestCertificate({
					domain: 'nonexistant.io',
					subdomains: ['12345', 'abcde'],
					ip: '1.2.3.4',
					email: 'nobody@nonexistant.io',
					renewing: false,
				})
				.then(_certs => {
					throw new Error(
						"The host doesn't exist and this should have failed!",
					);
				})
				.catch((error: CertificateClientError) => {
					return error.code.should.equal(
						CertificateClientErrorCodes.INVALID_TOKEN,
					);
				});
		});
	});

	// Attempt to generate a certificate and associated local IP address
	describe('Certificate generation and DNS A record', () => {
		const testIp = '10.1.2.3';
		const updatedIp = '10.1.2.4';
		const configRoot = `${process.cwd()}/test/testcert`;
		const subdomains = [`*.${uuid}`, `*.devices.${uuid}`];
		const dnsCheck = (ipAddress): PromiseLike<void> => {
			return dnsClient.retrieveARecords(domain).then(records => {
				const returnedDomainList = _.sortBy(
					_.map(records, record => record.domain),
				);
				const subdomainList = _.sortBy(
					_.map(subdomains, subdomain => `${subdomain}.${domain}`),
				);
				returnedDomainList.should.deep.eq(subdomainList);
				records.length.should.eq(subdomains.length);
				_.forEach(records, record => {
					record.ip.should.equal(ipAddress);
				});
			});
		};

		// Ensure cert directory is cleaned up post-test
		after(() => {
			return removeDirectory(configRoot);
		});

		it('should generate a valid certificate', () => {
			const client = new BalenaCertificateClient({
				dnsUpdateHost: dnsHost,
				dnsUpdatePort: dnsPort,
				authToken,
				configRoot,
			});

			return client
				.requestCertificate({
					domain,
					subdomains,
					ip: testIp,
					email,
					renewing: false,
				})
				.then(result => {
					if (!result) {
						throw new Error('`result` should not be undefined');
					}
					result.certificate.should.include('BEGIN CERTIFICATE');
					result.ca.should.include('BEGIN CERTIFICATE');
					result.privateKey.should.include('BEGIN RSA PRIVATE KEY');
				});
		}).timeout(140000);

		it('relevant domains should point to a valid A records', () => {
			// Get the record directly from the DNS client
			return dnsCheck(testIp);
		});

		it(
			'should not regenerate a certificate when a pre-existing one exists, but should ' +
				'update DNS A records',
			() => {
				// Add a test here to use the Route53 API to ensure the DNS IP is correct
				const client = new BalenaCertificateClient({
					dnsUpdateHost: dnsHost,
					dnsUpdatePort: dnsPort,
					authToken: process.env.CERT_TEST_AUTH_TOKEN || '',
					configRoot: `${process.cwd()}/test/testcert`,
				});

				return client
					.requestCertificate({
						domain,
						subdomains: [`*.${uuid}`, `*.devices.${uuid}`],
						ip: updatedIp,
						email,
						renewing: true,
					})
					.then(_result => {
						throw new Error('New certificate should not have been generated');
					})
					.catch((err: CertificateClientError) => {
						if (err.code !== CertificateClientErrorCodes.EXISTING_CERTIFICATE) {
							throw new Error(
								'Call should have failed with an EXISTING_CERTIFICATE error',
							);
						}
						return;
					});
			},
		).timeout(140000);

		it('relevant domains should point to updated and valid A records', () => {
			// Get the record directly from the DNS client
			return dnsCheck(updatedIp);
		});

		// This should finish in a timely manner, as no certificate or DNS update should
		// occur.
		it(
			'should not regenerate a certificate when a pre-existing one exists, and should ' +
				'not update DNS records when the IP address is the same',
			() => {
				// Add test to ensure the IP hasn't been updated
				const client = new BalenaCertificateClient({
					dnsUpdateHost: dnsHost,
					dnsUpdatePort: dnsPort,
					authToken: process.env.CERT_TEST_AUTH_TOKEN || '',
					configRoot: `${process.cwd()}/test/testcert`,
				});

				return client
					.requestCertificate({
						domain,
						subdomains: [`*.${uuid}`, `*.devices.${uuid}`],
						ip: updatedIp,
						email,
						renewing: true,
					})
					.then(_result => {
						throw new Error('New certificate should not have been generated');
					})
					.catch((err: CertificateClientError) => {
						if (err.code !== CertificateClientErrorCodes.EXISTING_CERTIFICATE) {
							throw new Error(
								'Call should have failed with an EXISTING_CERTIFICATE error',
							);
						}
						return;
					});
			},
		);
	});
});
