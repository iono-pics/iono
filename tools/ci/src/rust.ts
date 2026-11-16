import { dag, Container, Directory, Service } from "@dagger.io/dagger"

const DATABASE_URL = "postgres://iono:iono@postgres:5432/iono"

function postgres(): Service {
  return dag
    .container()
    .from("postgres:16")
    .withEnvVariable("POSTGRES_USER", "iono")
    .withEnvVariable("POSTGRES_PASSWORD", "iono")
    .withEnvVariable("POSTGRES_DB", "iono")
    .withExposedPort(5432)
    .asService({ useEntrypoint: true })
}

export function rustChecks(source: Directory): Container {
  return dag
    .container()
    .from("rust:1-slim")
    .withExec(["apt-get", "update"])
    .withExec([
      "apt-get",
      "install",
      "-y",
      "--no-install-recommends",
      "libssl-dev",
      "pkg-config",
    ])
    .withExec(["rustup", "component", "add", "rustfmt", "clippy"])
    .withMountedCache("/usr/local/cargo/registry", dag.cacheVolume("cargo-registry"))
    .withMountedCache("/opt/cargo-tools", dag.cacheVolume("cargo-tools"))
    .withEnvVariable("CARGO_INSTALL_ROOT", "/opt/cargo-tools")
    .withEnvVariable("PATH", "/opt/cargo-tools/bin:$PATH", { expand: true })
    .withExec(["cargo", "install", "--locked", "cargo-audit", "cargo-deny"])
    .withDirectory("/app", source)
    .withWorkdir("/app")
    .withMountedCache("/app/target", dag.cacheVolume("cargo-target"))
    .withExec(["cargo", "fmt", "--all", "--check"])
    .withExec(["cargo", "clippy", "--workspace", "--locked", "--", "-D", "warnings"])
    .withExec(["cargo", "audit", "--deny", "warnings"])
    .withExec(["cargo", "deny", "check"])
    .withServiceBinding("postgres", postgres())
    .withEnvVariable("DATABASE_URL", DATABASE_URL)
    .withExec(["cargo", "test", "--workspace", "--locked"])
}
