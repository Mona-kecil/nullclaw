# Native Discord commands

The Discord gateway accepts native commands from the configured allowlist. Native commands use the same account, channel, thread, and session route as text commands. Explicit commands work when `require_mention` is enabled. Bot users cannot invoke native commands.

Each accepted invocation receives a completed private receipt. For `/status` the receipt says `Received /status. Command output appears in this channel.` The command output appears as a normal channel message. The receipt confirms receipt, not command completion. A shutdown or full inbound queue can prevent execution after the receipt.

The catalog is `src/channels/discord_commands.json`. It defines 52 Discord commands and also generates Discord help. Commands with arguments expose one optional string named `args`, with a 2000-byte transport limit. Telegram-only commands are excluded.

Deploy the binary before registering commands. Registration uses Bun with no package installation.

```sh
bun scripts/register_discord_commands.mjs --self-test
bun scripts/register_discord_commands.mjs --dry-run
bun scripts/register_discord_commands.mjs --apply --guild GUILD_ID --account ACCOUNT_NAME
```

`--dry-run` reads the catalog and makes no network calls. `--apply` reads `~/.nullclaw/config.json` in process. Use `--config PATH` for a different private config file. It accepts `channels.discord.accounts` or the inline single-account form. With several accounts, pass `--account`. A configured `guild_id` must match `--guild`.

The script resolves the bot application, reads the guild definitions, and saves a mode-0600 backup under `~/.nullclaw/backups/discord-commands/`. Use `--backup PATH` to choose a new backup file. Existing files are never overwritten. The script then upserts the catalog entries and verifies a readback. Managed definitions clear command-level default member permissions and the NSFW flag. Guild command overrides remain under Discord administration. Unknown commands remain in place. An unchanged second run sends no command writes. It never registers global commands.

The script prints names, counts, and status codes. It reads the bot token from the private config and never accepts one on the command line. Encrypted token fields require a separate private config with a plaintext bot token. Keep that file outside the source tree. Each REST request has a ten-second timeout. A failed or rate-limited run exits with a status code; rerun it to finish the remaining updates.

The native callback has a two-second curl timeout. Interaction credentials travel through curl stdin and stay out of the bus metadata. Tests inject a private callback and make no network calls.
