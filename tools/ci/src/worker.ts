import { dag, Container, Directory } from "@dagger.io/dagger"

export function workerChecks(source: Directory): Container {
  return dag
    .container()
    .from("node:22-slim")
    .withExec(["corepack", "enable"])
    .withDirectory("/app", source)
    .withWorkdir("/app")
    .withMountedCache("/app/node_modules", dag.cacheVolume("worker-node-modules"))
    .withExec(["yarn", "install", "--immutable"])
    .withExec(["yarn", "tsc", "--noEmit"])
}
