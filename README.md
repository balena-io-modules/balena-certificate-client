# balena-certificate-client
Client/Server library for registering device certificates.

This library provides a method for creating and retrieving certificates for devices
based upon the `katapult` toolchain and `balena-on-balena` framework.

It uses the Let's Encrypt platform for generating certificates (which are valid for 90
days). The library simplifies the generation process, including automating the DNS
challenges required for wildcarded certificates which the Development Environment
utilises, as well as writing A records to match a given IP address where the
device is located on an engineer's local subnet.

## Usage

### BalenaCertificateClient

The library consists of a class which exposes a single method for requesting certificates.
A single instance of the class can be used to generate certificates for many different
devices, if required.

Constructor Object Arguments:
* `dnsUpdateHost` - The hostname where the DNS Update Service is located
* `dnsUpdatePort` - The port on which the DNS Update Service is listening
* `authToken` - An authorisation token unique to the user requesting the certificates
* `configRoot` - An absolute path to where the library should store Let's Encrypt
    configuration data

### BalenaCertificateClient.requestCertificate
This method:
1. Request a certificate for a given domain/subdomains from Let's Encrypt
2. Respond to DNS challenges for the domain, assuming it can contact an appropriate
    DNS Update Service
3. Retrieve and store the certificate
4. Create/Update a DNS A record for the specified sub-domain pointing to the
    local IP of a device

**Arguments Object:**
* `domain` - The parent domain of the certificates to produce
* `subdomains`[optional] - An array of subdomains that will be used as Subject Alternative
    Names (SANs) in the certificate. Note that the first subdomain found will be used
    as the Common Name (CN). Should no subdomains be passed, the certificate will be
    created for the `domain` passed.
* `ip` - The IP address of the local device
* `renewing` - *Must* be `true` if the certificate already exists, else `false`
* `email` - An email address to register with Let's Encrypt for the certificate
    generation/renewal. This must be valid
* `outputLocation`[optional] - If set, the CA, EEC and private key will be written
    into this location in appropriately named files (`[ca|certificate|private-key].pem`)

**Returns:**
Object consisting of:
* `ca` - A PEM encoded CA certificate that signed the EEC certificate
* `certificate` - A PEM encoded EEC certificate
* `privateKey` - A PEM encoded private key used to sign the CSR for the EEC certificate

**Note:** Whilst the object returned includes a `privateKey` property, the filename requested by an `outputLocation` parameter to the `requestCertificate()` method will
be saved as `private-key.pem`.

### Usage

```typescript
import { BalenaCertificateClient } from 'balena-certificate-client';

const certClientInst = new BalenaCertificateClient({
    dnsUpdateHost: 'localhost',
    dnsUpdatePort: 443,
    authToken: '12345',
    configRoot: `${process.cwd()}/config`
});

certClientInst.requestCertificate({
    domain: 'somedomain.io',
    subdomains: [
        '*.1234567890abcdef',
        '*.devices.1234567890abcdef',
    ],
    ip: '1.2.3.4',
    email: 'nobody@nowhere.org',
    renewing: false,
    outputLocation: '/some/other/path'
}).then((certificates) => {
    console.log(certificates.ca);
    console.log(certificates.certificate);
    console.log(certificates.privateKey);
});
```
