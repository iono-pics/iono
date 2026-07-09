import { Container, getContainer } from "@cloudflare/containers";

interface Env {
	SERVER_CONTAINER: DurableObjectNamespace<ServerContainer>;
}

export class ServerContainer extends Container<Env> {
	defaultPort = 8080;
	sleepAfter = "10m";
}

export default {
	async fetch(request: Request, env: Env) {
		const container = getContainer(env.SERVER_CONTAINER);
		return container.fetch(request);
	},
};
