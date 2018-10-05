declare module 'le-store-certbot' {
	export interface CreateOptions {
		configDir: string;
		privKeyPath?: string;
		fullchainPath?: string;
		certPath?: string;
		chainPath?: string;
		logsDir?: string;
		webrootPath?: string;
		debug?: boolean;
	}

	export function create(opts: CreateOptions): any;
}
