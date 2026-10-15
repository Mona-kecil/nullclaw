# Mono fork

This fork keeps the changes used by Mono. The `mono` branch starts at upstream
`v2026.5.29`, commit `b25c6eb59f845f4f8cdbb50d6f284cb56d723435`.

- `origin` is `https://github.com/Mona-kecil/nullclaw.git`.
- `upstream` is `https://github.com/nullclaw/nullclaw.git`.

## Local changes

- Bound Discord typing requests so cleanup cannot stall later replies.
- Accept native Discord commands through the existing session and access checks.
- Generate Discord help from the same 52-command catalog used for registration.

See [Discord command setup](docs/en/discord-native-commands.md).

## Maintain

Check upstream weekly with `git fetch upstream --tags`. Review releases and
changes before merging a chosen upstream tag or commit into `mono`. Keep fork
changes in separate commits so they can be dropped when upstream includes them.

Use Zig 0.16.0. Before pushing or replacing the running binary, run:

```sh
zig build test --summary all
bun scripts/register_discord_commands.mjs --self-test
zig build -Doptimize=ReleaseSmall -Dversion=2026.5.29-mono
```

The imported source passed 7,330 tests with nine skipped and a ReleaseSmall
build on macOS arm64. The Discord catalog was verified against the live server.

Keep configuration, credentials, chat databases, and build caches outside Git.
Retain the previous binary when deploying so the service can roll back.
