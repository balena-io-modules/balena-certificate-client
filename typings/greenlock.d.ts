declare module 'greenlock' {
	export interface Challenge {
		getOptions: () => any;
		set: (
			args: any,
			domain: any,
			challenge: any,
			keyAuthorization: any,
			callback: () => any,
		) => void;
		get: (
			defaults: any,
			domain: any,
			challenge: any,
			callback: () => void,
		) => void;
		remove: (
			args: any,
			domain: any,
			challenge: any,
			callback: () => void,
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
