declare module 'greenlock' {
	export interface Challenge {
		getOptions: () => CreateOptions;
		set: (
			args: CreateOptions,
			domain: string,
			challenge: string,
			keyAuthorization: string,
			callback: (err: Error | null, opt?: CreateOptions) => void,
		) => void;
		get: (
			defaults: any,
			domain: string,
			challenge: string,
			callback: (err: Error | null, opt?: CreateOptions) => void,
		) => void;
		remove: (
			args: any,
			domain: string,
			challenge: string,
			callback: (err: Error | null, opt?: CreateOptions) => void,
		) => void;
	}

	export interface CreateOptions {
		version?: string;
		server?: string;
		store?: any;
		challenges?: { [type: string]: Challenge };
		challengeType?: string;
		renewWithin?: number;
		renewBy?: number;
		debug?: boolean;
	}

	export interface CertificateOptions {
		domains: string[];
		email?: string;
		agreeTos?: string | boolean;
		rsaKeySize?: number;
		challengeType?: string;
	}

	export interface CertificateResults {
		privkey: string;
		cert: string;
		chain: string;
		issuedAt: number;
		expiresAt: number;
		subject: string;
		altnames: string[];
	}

	export interface GreenlockInstance {
		register: (registration: CertificateOptions) => Promise<CertificateResults>;
		check: (check: CertificateOptions) => Promise<CertificateResults>;
	}

	export function create(opts: CreateOptions): GreenlockInstance;
}
