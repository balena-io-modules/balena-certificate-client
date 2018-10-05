# balena-devenv-certs
Client/Server library for registering Devenv certificates

This library provides a method for creating and retrieving certificates for Development
Environments based upon the `katapult` toolchain and `balena-on-balena` framework.

It uses the Let's Encrypt platform for generating certificates (which are valid for 90
days). The library simplifies the generation process, including automating the DNS
challenges required for wildcarded certificates which the Development Environment
utilises, as well as writing A records to match a given IP address where the
Devenv is located on an engineer's local subnet.

## Usage

### BalenaDevenvCertificates

The library consists of a class which exposes a single method for requesting certificates.
A single instance of the class can be used to generate certificates for many different
Devenvs, if required.

Constructor Object Arguments:
* `dnsUpdateHost` - The hostname where the DNS Update Service is located
* `dnsUpdatePort` - The port on which the DNS Update Service is listening
* `authToken` - An authorisation token unique to the user requesting the certificates
* `configRoot` - An absolute path to where the library should store Let's Encrypt
    configuration data

### BalenaDevenvCertificates.requestCertificate
This method:
1. Request a certificate for a given sub-domain from Let's Encrypt
2. Respond to DNS challenges for the domain, assuming it can contact an appropriate
    DNS Update Service
3. Retrieve and store the certificate
4. Create/Update a DNS A record for the specified sub-domain pointing to the
    local IP of a Devenv

**Arguments Object:**
* `uuid` - The UUID of the Devenv being registered
* `domain` - The domain that owns the `uuid` sub-domain
* `ip` - The IP address of the local Devenv
* `renewing` - *Must* be `true` if the certificate already exists, else `false`
* `email` - An email address to register with Let's Encrypt for the certificate
    generation/renewal. This must be valid
* `outputLocation`[optional] - If set, the CA, EEC and private key will be written
    into this location in appropriately named files (`[ca|certificate|privateKey].pem`)

**Returns:**
Object consisting of:
* `ca` - A PEM encoded CA certificate that signed the EEC certificate
* `certificate` - A PEM encoded EEC certificate
* `privateKey` - A PEM encoded private key used to sign the CSR for the EEC certificate

### JavaScript Usage

```javascript
const BalenaDevenvCertificates = require('balena-devenv-certificates').BalenaDevenvCertificates;

const devenvCertsInst = new BalenaDevenvCertificates({
    dnsUpdateHost: 'exampleserver.net',
    dnsUpdatePort: 443,
    authToken: 'abcdef1234567890',
    configRoot: '/some/path'
});

devenvCertsInst.requestCertificate({
    uuid: '1234567890abcdef',
    domain: 'somedomain.io',
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

### TypeScript Usage

```typescript
import { BalenaDevenvCertificates } from 'balena-devenv-certificates';

const devenvCertsInst = new BalenaDevenvCertificates({
    dnsUpdateHost: 'localhost',
    dnsUpdatePort: 443,
    authToken: '12345',
    configRoot: `${process.cwd()}/config`
});

devenvCertsInst.requestCertificate({
    uuid: '1234567890abcdef',
    domain: 'somedomain.io',
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
