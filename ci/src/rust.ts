import { dag, Container, Directory } from "@dagger.io/dagger"

export function rustChecks(source: Directory): Container {
  return dag
    .container()
    .from("rust:1-slim")
    .withExec(["rustup", "component", "add", "rustfmt", "clippy"])
    .withMountedCache("/usr/local/cargo/registry", dag.cacheVolume("cargo-registry"))
    .withDirectory("/app", source)
    .withWorkdir("/app")
    .withMountedCache("/app/target", dag.cacheVolume("cargo-target"))
    .withExec(["cargo", "fmt", "--all", "--check"])
    .withExec(["cargo", "clippy", "--workspace", "--", "-D", "warnings"])
    .withExec(["cargo", "test", "--workspace"])
}
