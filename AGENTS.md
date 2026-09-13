# 3ax-ui-orchestrator

Project guide for AI assistants. The repo is empty apart from this guide; the policies below apply from the first commit.

## Testing

Legacy code stays untested; a fix in it ships with a unit test reproducing the bug; new functionality ships with unit tests and Playwright e2e tests against the repo's Docker image. See `docs/agents/testing.md` before writing or reviewing tests.

## Related repos

Panel and proxy front: [SBKubric/3ax-ui-proxy](https://github.com/SBKubric/3ax-ui-proxy) (glossary `CONTEXT.md`, ADRs, issue tracker conventions in `docs/agents/`). Monitoring: [SBKubric/3ax-ui-monitoring](https://github.com/SBKubric/3ax-ui-monitoring). Branches are named `<issue number>-<name>`.
