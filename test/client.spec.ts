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
///<reference path="../typings/greenlock.d.ts"/>
///<reference path="../typings/le-store-certbot.d.ts"/>
import * as Bluebird from 'bluebird';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as _ from 'lodash';
import 'mocha';
import * as DNS from 'dns';

import {
	BalenaDevenvCertificateClient,
	CertificateClientError,
	CertificateClientErrorCodes,
} from '../src/client';

// Include Chai and ensure that `should` is defined
chai.use(chaiAsPromised);
const { should } = chai.should();
should.exist;

const dnsHost = process.env.DEVENV_CERT_TEST_HOST || '';
const dnsPort = parseInt(process.env.DEVENV_CERT_TEST_PORT || '0', 10);
const domain = process.env.DEVENV_CERT_TEST_DOMAIN || '';
const email = process.env.DEVENV_CERT_TEST_EMAIL || '';

describe('Devenv Certificate Client', () => {
	const uuid = '1234567890';

	// We should fail if the host or the authentication token is invalid
	describe('Invalid config/authorisation details', () => {
		it('should fail for bad DNS service host details', () => {
			try {
				new BalenaDevenvCertificateClient({
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
			const client = new BalenaDevenvCertificateClient({
				dnsUpdateHost: dnsHost,
				dnsUpdatePort: dnsPort,
				authToken: '1234',
				configRoot: `${process.cwd()}/test/invalidtoken`,
			});

			return client
				.requestCertificate({
					uuid,
					domain: 'nonexistant.io',
					ip: '1.2.3.4',
					email: 'nobody@nonexistant.io',
					renewing: false,
				})
				.then(_certs => {
					return new Error(
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
		const testIP = '10.1.2.3';

		it('should generate a valid certificate', () => {
			const client = new BalenaDevenvCertificateClient({
				dnsUpdateHost: dnsHost,
				dnsUpdatePort: dnsPort,
				authToken: process.env.DEVENV_CERT_TEST_AUTH_TOKEN || '',
				configRoot: `${process.cwd()}/test/testcert`,
			});

			return client
				.requestCertificate({
					uuid: '1234567890',
					domain,
					ip: '10.1.2.3',
					email,
					renewing: false,
				})
				.then(result => {
					result.certificate.should.include('BEGIN CERTIFICATE');
					result.ca.should.include('BEGIN CERTIFICATE');
					result.privateKey.should.include('BEGIN RSA PRIVATE KEY');
				});
		}).timeout(140000);

		it('relevant hostname URIs should point to a valid A records', () => {
			return Bluebird.map(
				[
					`api.${uuid}.${process.env.DEVENV_CERT_TEST_DOMAIN}`,
					`actions.devices.${uuid}.${process.env.DEVENV_CERT_TEST_DOMAIN}`,
				],
				uri => {
					return Bluebird.fromCallback<string>(cb => {
						return DNS.lookup(uri, cb);
					}).then((ipAddress: string) => {
						ipAddress.should.equal(testIP);
					});
				},
			);
		});
	});
});
