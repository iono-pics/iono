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
      ignore: ["**/node_modules", "**/target", "web", "docs", "mobile", "ci"],
    })
    source: Directory,
  ): Promise<string> {
    await Promise.all([
      rustChecks(source.directory("server")).sync(),
      workerChecks(source.directory("infra/server")).sync(),
    ])
    return "all checks passed"
  }
}
