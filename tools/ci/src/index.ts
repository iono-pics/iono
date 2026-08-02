import { Container, Directory, argument, object, func } from "@dagger.io/dagger"

import { rustChecks } from "./rust"
import { workerChecks } from "./worker"

@object()
export class Iono {
  @func()
  rust(source: Directory): Container {
    return rustChecks(source)
  }

  @func()
  worker(source: Directory): Container {
    return workerChecks(source)
  }

  @func()
  async ci(
    @argument({
      defaultPath: "/",
      ignore: [
        "**/node_modules",
        "**/target",
        "apps/web",
        "apps/docs",
        "apps/mobile",
        "tools/ci",
      ],
    })
    source: Directory,
  ): Promise<string> {
    await Promise.all([
      rustChecks(source.directory("apps/server")).sync(),
      workerChecks(source.directory("apps/server/infra")).sync(),
    ])
    return "all checks passed"
  }
}
