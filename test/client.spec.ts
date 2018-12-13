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

// Include Chai and ensure that `should` is defined
chai.use(chaiAsPromised);
const { should } = chai.should();
should.exist;

const dnsHost = process.env.CERT_TEST_HOST || '';
const dnsPort = parseInt(process.env.CERT_TEST_PORT || '0', 10);
const domain = process.env.CERT_TEST_DOMAIN || '';
const email = process.env.CERT_TEST_EMAIL || '';

// Utility function for removing certificate directories
function removeDirectory(dir: string): Bluebird<void> {
	return Bluebird.fromCallback((cb: (err: Error, result?: any) => void) => {
		rimraf(dir, cb);
	});
}

describe('Certificate Client', () => {
	const uuid = '1234567890';

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

		// Ensure cert directory is cleaned up post-test
		after(() => {
			return removeDirectory(configRoot);
		});

		it('should generate a valid certificate', () => {
			const client = new BalenaCertificateClient({
				dnsUpdateHost: dnsHost,
				dnsUpdatePort: dnsPort,
				authToken: process.env.CERT_TEST_AUTH_TOKEN || '',
				configRoot,
			});

			return client
				.requestCertificate({
					domain,
					subdomains: [`*.${uuid}`, `*.devices.${uuid}`],
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

		it('relevant hostname URIs should point to a valid A records', () => {
			return Bluebird.map(
				[
					`api.${uuid}.${process.env.CERT_TEST_DOMAIN}`,
					`actions.devices.${uuid}.${process.env.CERT_TEST_DOMAIN}`,
				],
				uri => {
					return Bluebird.fromCallback<string>(cb => {
						return DNS.lookup(uri, cb);
					}).then((ipAddress: string) => {
						ipAddress.should.equal(testIp);
					});
				},
			);
		});

		// Note that we don't test for the updated IP address here. This is because
		// we'd need to clear the DNS cache first, which is OS specific and also could
		// affect it's immediate operation. We take the successful passing of this test to
		// imply the A record has been correctly updated.
		it(
			'should not regenerate a certificate when a pre-existing one exist, but should ' +
				'update DNS A records',
			() => {
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
	});
});
