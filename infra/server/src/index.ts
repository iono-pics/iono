import { Container, getContainer } from "@cloudflare/containers";

const GATEWAY_PORT = 8080;
const INGEST_PORT = 8081;
const VIEWER_PORT = 8082;

interface Env {
	SERVER_CONTAINER: DurableObjectNamespace<ServerContainer>;
	API_HOST: string;
	INGEST_HOST: string;
	DATABASE_URL: string;
	S3_BUCKET: string;
	S3_REGION: string;
	S3_ENDPOINT?: string;
	S3_ACCESS_KEY_ID: string;
	S3_SECRET_ACCESS_KEY: string;
	JWT_SECRET: string;
	RUST_LOG?: string;
}

export class ServerContainer extends Container<Env> {
	defaultPort = GATEWAY_PORT;
	requiredPorts = [GATEWAY_PORT, INGEST_PORT, VIEWER_PORT];
	envVars = {
		DATABASE_URL: this.env.DATABASE_URL,
		S3_BUCKET: this.env.S3_BUCKET,
		S3_REGION: this.env.S3_REGION,
		...(this.env.S3_ENDPOINT ? { S3_ENDPOINT: this.env.S3_ENDPOINT } : {}),
		S3_ACCESS_KEY_ID: this.env.S3_ACCESS_KEY_ID,
		S3_SECRET_ACCESS_KEY: this.env.S3_SECRET_ACCESS_KEY,
		JWT_SECRET: this.env.JWT_SECRET,
		...(this.env.RUST_LOG ? { RUST_LOG: this.env.RUST_LOG } : {}),
	};

	override async fetch(request: Request): Promise<Response> {
		return this.containerFetch(request, portFor(new URL(request.url), this.env));
	}
}

function portFor(url: URL, env: Env): number {
	if (url.hostname === env.INGEST_HOST) {
		return INGEST_PORT;
	}
	if (url.hostname === env.API_HOST) {
		return GATEWAY_PORT;
	}
	return VIEWER_PORT;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const container = getContainer(env.SERVER_CONTAINER);
		const url = new URL(request.url);

		if (request.method !== "GET" || url.hostname === env.API_HOST || url.hostname === env.INGEST_HOST) {
			return container.fetch(request);
		}

		const cache = caches.default;
		const hit = await cache.match(request);
		if (hit) {
			return hit;
		}

		const response = await container.fetch(request);
		if (response.status === 200 && response.headers.get("Cache-Control")?.includes("public")) {

			// TODO: when a file is deleted we should purge the files urls
			// thru cf purge by url, immutable cached files outlive db rows
			ctx.waitUntil(cache.put(request, response.clone()));
		}
		return response;
	},
};
