import { Container, getContainer } from "@cloudflare/containers";

const GATEWAY_PORT = 8080;
const INGEST_PORT = 8081;
const VIEWER_PORT = 8082;
const JANITOR_PORT = 8083;

// every setting crates/core/src/config.rs reads. forwarded to the container
// when set, so a new setting only has to be added here and in wrangler
const FORWARDED_ENV = [
	"DATABASE_URL",
	"DATABASE_MAX_CONNECTIONS",
	"S3_BUCKET",
	"S3_REGION",
	"S3_ENDPOINT",
	"S3_ACCESS_KEY_ID",
	"S3_SECRET_ACCESS_KEY",
	"JWT_SECRET",
	"JWT_ACCESS_TTL_MINUTES",
	"REFRESH_TOKEN_TTL_DAYS",
	"FILE_ENCRYPTION_KEY",
	"FILE_ENCRYPTION_KEY_VERSION",
	"FILE_ENCRYPTION_PREVIOUS_KEYS",
	"MAINTENANCE_TOKEN",
	"PUBLIC_INGEST_URL",
	"WEBAUTHN_RP_ID",
	"WEBAUTHN_RP_ORIGIN",
	"AUTH_RATE_LIMIT_SECONDS_PER_REQUEST",
	"AUTH_RATE_LIMIT_BURST",
	"INGEST_RATE_LIMIT_SECONDS_PER_REQUEST",
	"INGEST_RATE_LIMIT_BURST",
	"RECOVERY_WINDOW_DAYS",
	"TOTP_RECOVERY_CODE_COUNT",
	"OAUTH_FLOW_STATE_TTL_MINUTES",
	"WEBAUTHN_CEREMONY_TTL_MINUTES",
	"MAX_PASTE_SIZE_KB",
	"MAX_UPLOAD_SIZE_MB",
	"MAX_IMAGE_DECODE_SIZE_MB",
	"SWEEP_BATCH_SIZE",
	"ENCRYPT_BACKFILL_BATCH_SIZE",
	"ENCRYPT_BACKFILL_MAX_OBJECT_MB",
	"BROWSER_CACHE_MAX_AGE_SECONDS",
	"EDGE_CACHE_MAX_AGE_SECONDS",
	"CLOUDFLARE_ZONE_ID",
	"CLOUDFLARE_API_TOKEN",
	"STRIPE_API_KEY",
	"STRIPE_PORTAL_RETURN_URL",
	"DISCORD_CLIENT_ID",
	"DISCORD_CLIENT_SECRET",
	"DISCORD_REDIRECT_URI",
	"DISCORD_SUCCESS_REDIRECT_URL",
	"RUST_LOG",
] as const;

// the container panics at boot without these, so say which is missing here
const REQUIRED_ENV = [
	"DATABASE_URL",
	"JWT_SECRET",
	"FILE_ENCRYPTION_KEY",
	"MAINTENANCE_TOKEN",
	"WEBAUTHN_RP_ID",
	"WEBAUTHN_RP_ORIGIN",
] as const;

type ForwardedEnv = Partial<Record<(typeof FORWARDED_ENV)[number], string>>;

interface Env extends ForwardedEnv {
	SERVER_CONTAINER: DurableObjectNamespace<ServerContainer>;
	INGEST_CONTAINER: DurableObjectNamespace<IngestContainer>;
	VIEWER_CONTAINER: DurableObjectNamespace<ViewerContainer>;
	API_HOST: string;
	INGEST_HOST: string;
	MAINTENANCE_TOKEN: string;
	// how many instances each pool spreads over, each at most its class's
	// max_instances in wrangler
	CORE_INSTANCES?: string;
	INGEST_INSTANCES?: string;
	VIEWER_INSTANCES?: string;
}

function containerEnv(env: Env, services: string): Record<string, string> {
	const missing = REQUIRED_ENV.filter((key) => !env[key]);
	if (missing.length > 0) {
		throw new Error(`missing container settings: ${missing.join(", ")}`);
	}
	return {
		...Object.fromEntries(
			FORWARDED_ENV.flatMap((key) => {
				const value = env[key];
				return value ? [[key, value]] : [];
			}),
		),
		IONO_SERVICES: services,
	};
}

// one image, three classes. each runs only its own services so uploads, page
// views and the api scale and fail independently

// the api and the janitor. every instance runs a janitor, but only the cron
// talks to one, on the first instance
export class ServerContainer extends Container<Env> {
	defaultPort = GATEWAY_PORT;
	requiredPorts = [GATEWAY_PORT];
	envVars = containerEnv(this.env, "gateway janitor");

	async sweep(): Promise<number> {
		const res = await this.containerFetch(
			"http://janitor/sweep",
			{
				method: "POST",
				headers: { Authorization: `Bearer ${this.env.MAINTENANCE_TOKEN}` },
			},
			JANITOR_PORT,
		);
		return res.status;
	}
}

export class IngestContainer extends Container<Env> {
	defaultPort = INGEST_PORT;
	requiredPorts = [INGEST_PORT];
	envVars = containerEnv(this.env, "ingest");
}

export class ViewerContainer extends Container<Env> {
	defaultPort = VIEWER_PORT;
	requiredPorts = [VIEWER_PORT];
	envVars = containerEnv(this.env, "viewer");
}

function instanceCount(value: string | undefined, fallback: number): number {
	const parsed = Number.parseInt(value ?? "", 10);
	return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

// the same client always reaches the same instance. rate limits and the
// viewer's unlock cache live in process memory, so spreading one client over
// n instances would quietly multiply every per client limit by n
function instanceFor(request: Request, pool: string, count: number): string {
	const client = request.headers.get("CF-Connecting-IP") ?? "";
	let hash = 0x811c9dc5;
	for (let i = 0; i < client.length; i++) {
		hash = Math.imul(hash ^ client.charCodeAt(i), 0x01000193);
	}
	return `${pool}-${(hash >>> 0) % count}`;
}

function containerFor(request: Request, url: URL, env: Env): DurableObjectStub<Container<Env>> {
	if (url.hostname === env.INGEST_HOST) {
		const name = instanceFor(request, "ingest", instanceCount(env.INGEST_INSTANCES, 2));
		return getContainer(env.INGEST_CONTAINER, name);
	}
	if (url.hostname === env.API_HOST) {
		const name = instanceFor(request, "core", instanceCount(env.CORE_INSTANCES, 2));
		return getContainer(env.SERVER_CONTAINER, name);
	}
	const name = instanceFor(request, "viewer", instanceCount(env.VIEWER_INSTANCES, 3));
	return getContainer(env.VIEWER_CONTAINER, name);
}

// tags name internal ids, they are for the cache and not for clients
function withoutCacheTags(response: Response): Response {
	if (!response.headers.has("Cache-Tag")) {
		return response;
	}
	const stripped = new Response(response.body, response);
	stripped.headers.delete("Cache-Tag");
	return stripped;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		const container = containerFor(request, url, env);

		if (request.method !== "GET" || url.hostname === env.API_HOST || url.hostname === env.INGEST_HOST) {
			return container.fetch(request);
		}

		const cache = caches.default;
		const hit = await cache.match(request);
		if (hit) {
			return withoutCacheTags(hit);
		}

		const response = await container.fetch(request);
		if (response.status === 200 && response.headers.get("Cache-Control")?.includes("public")) {
			// stored with its Cache-Tag header, which is what lets deletion
			// purge it from every data center by tag
			ctx.waitUntil(cache.put(request, response.clone()));
		}
		return withoutCacheTags(response);
	},

	async scheduled(_controller: ScheduledController, env: Env) {
		const status = await getContainer(env.SERVER_CONTAINER, "core-0").sweep();
		console.log(`janitor sweep: ${status}`);
	},
};
