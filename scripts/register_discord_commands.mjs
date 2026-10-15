#!/usr/bin/env bun
import { readFile, mkdir, open, mkdtemp, rm, stat } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

const catalogPath = new URL('../src/channels/discord_commands.json', import.meta.url);
const API = 'https://discord.com/api/v10';
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const snowflake = value => typeof value === 'string' && /^[0-9]{1,32}$/.test(value);
class RegistrationError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new RegistrationError(code); };

function validateCatalog(catalog) {
  if (!Array.isArray(catalog) || catalog.length === 0) fail('invalid_catalog');
  const names = new Set();
  for (const command of catalog) {
    if (!object(command) || Object.keys(command).some(key => !['type', 'name', 'description', 'options', 'default_member_permissions', 'nsfw'].includes(key)) ||
        command.type !== 1 || command.default_member_permissions !== null || command.nsfw !== false || typeof command.name !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(command.name) ||
        typeof command.description !== 'string' || command.description.length < 1 || command.description.length > 100 || names.has(command.name)) fail('invalid_catalog');
    names.add(command.name);
    if (command.options !== undefined && (!Array.isArray(command.options) || command.options.length > 1)) fail('invalid_catalog');
    for (const option of command.options ?? []) {
      if (!object(option) || Object.keys(option).some(key => !['type', 'name', 'description', 'required', 'max_length'].includes(key)) ||
          option.type !== 3 || option.name !== 'args' || option.required !== false || !Number.isInteger(option.max_length) || option.max_length < 1 || option.max_length > 6000 ||
          typeof option.description !== 'string' || option.description.length < 1 || option.description.length > 100) fail('invalid_catalog');
    }
  }
  return catalog;
}

function selectAccount(config, accountId) {
  const discord = config?.channels?.discord;
  if (!object(discord)) fail('discord_config_missing');
  const accounts = object(discord.accounts) ? Object.entries(discord.accounts) : [[discord.account_id ?? 'default', discord]];
  const match = accountId ? accounts.filter(([id]) => id === accountId) : accounts;
  if (match.length !== 1 || !object(match[0][1])) fail('select_one_account_with_account');
  const account = match[0][1];
  if (typeof account.token !== 'string' || account.token.length === 0 || /[\r\n]/.test(account.token) || /^(enc:|enc2:)/.test(account.token)) fail('plain_bot_token_required');
  if (account.guild_id !== undefined && account.guild_id !== null && !snowflake(account.guild_id)) fail('invalid_configured_guild');
  return account;
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!object(value)) return value;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, stable(item)]));
}
function comparable(command) {
  return { type: command.type ?? 1, name: command.name, description: command.description,
    default_member_permissions: command.default_member_permissions ?? null, nsfw: command.nsfw ?? false,
    default_permission: command.default_permission ?? true,
    options: (command.options ?? []).map(option => {
      const normalized = { ...option, required: option.required ?? false };
      for (const [key, value] of Object.entries(normalized)) {
        if (value === null || (['choices', 'options'].includes(key) && Array.isArray(value) && value.length === 0) || (key === 'autocomplete' && value === false)) delete normalized[key];
      }
      return normalized;
    }) };
}
const equalCommand = (left, right) => JSON.stringify(stable(comparable(left))) === JSON.stringify(stable(comparable(right)));

function makeRequest(token, fetcher = fetch) {
  return async (method, path, body) => {
    let response;
    try {
      response = await fetcher(`${API}${path}`, { method, headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
    } catch { fail('request_failed'); }
    if (!response.ok) fail(`http_${response.status}`);
    try { return await response.json(); } catch { fail('invalid_api_response'); }
  };
}

async function saveBackup(path, commands) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const file = await open(path, 'wx', 0o600);
  try {
    await file.chmod(0o600);
    await file.writeFile(`${JSON.stringify(commands, null, 2)}\n`);
    await file.sync();
  } finally { await file.close(); }
}

async function registerCommands({ catalog, guild, request, backup }) {
  validateCatalog(catalog);
  if (!snowflake(guild)) fail('invalid_guild');
  const app = await request('GET', '/oauth2/applications/@me');
  if (!object(app) || !snowflake(app.id)) fail('invalid_application');
  const path = `/applications/${app.id}/guilds/${guild}/commands`;
  const before = await request('GET', path);
  if (!Array.isArray(before)) fail('invalid_command_list');
  await backup(before);
  let changed = 0;
  for (const command of catalog) {
    const existing = before.find(item => item.name === command.name && (item.type ?? 1) === command.type);
    if (existing && equalCommand(existing, command)) continue;
    await request('POST', path, command);
    changed += 1;
  }
  const after = await request('GET', path);
  if (!Array.isArray(after)) fail('invalid_command_list');
  for (const command of catalog) {
    const found = after.find(item => item.name === command.name && (item.type ?? 1) === command.type);
    if (!found || !equalCommand(found, command)) fail('readback_mismatch');
  }
  for (const previous of before) {
    const managed = catalog.some(command => command.name === previous.name && command.type === (previous.type ?? 1));
    if (!managed && !after.some(command => command.id === previous.id && JSON.stringify(stable(command)) === JSON.stringify(stable(previous)))) fail('unmanaged_command_changed');
  }
  return { changed, verified: catalog.length };
}

function parseArgs(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (['--apply', '--dry-run', '--self-test', '--help'].includes(arg)) {
      if (options[arg]) fail('duplicate_option');
      options[arg] = true;
    } else if (['--guild', '--account', '--config', '--backup'].includes(arg)) {
      if (options[arg] || !args[i + 1] || args[i + 1].startsWith('--')) fail('invalid_arguments');
      options[arg] = args[++i];
    } else fail('invalid_arguments');
  }
  if (options['--apply'] && options['--dry-run']) fail('choose_apply_or_dry_run');
  return options;
}

async function selfTest(catalog) {
  assert.equal(catalog.length, 52);
  assert.ok(catalog.some(command => command.name === 'config'));
  assert.ok(!catalog.some(command => ['bind', 'topic', 'topics', 'topic-map'].includes(command.name)));
  assert.throws(() => validateCatalog([...catalog, catalog[0]]), /invalid_catalog/);
  assert.throws(() => validateCatalog([{ ...catalog[0], options: [{ type: 3, name: 'args', description: 'args', required: true }] }]), /invalid_catalog/);
  assert.throws(() => parseArgs(['--apply', '--dry-run']), /choose_apply/);
  assert.throws(() => selectAccount({ channels: { discord: { accounts: { a: { token: 'a' }, b: { token: 'b' } } } } }), /select_one/);
  assert.equal(selectAccount({ channels: { discord: { accounts: { a: { token: 'test-token' } } } } }, 'a').token, 'test-token');
  const unknown = { id: '77', type: 1, name: 'other', description: 'Keep this command', options: [] };
  const sameNameOtherType = { id: '78', type: 2, name: catalog[0].name };
  let commands = [unknown, sameNameOtherType, { ...structuredClone(catalog[0]), id: '79', description: 'Old description', version: '1' }];
  const calls = [];
  let backups = 0;
  const fetcher = async (url, options) => {
    assert.ok(options.signal instanceof AbortSignal);
    assert.equal(options.headers.Authorization, 'Bot test-token');
    calls.push([options.method, url]);
    if (url.endsWith('/oauth2/applications/@me')) return Response.json({ id: '123' });
    assert.equal(url, `${API}/applications/123/guilds/456/commands`);
    if (options.method === 'GET') return Response.json(commands);
    assert.equal(backups, 1);
    const body = JSON.parse(options.body);
    commands = commands.filter(command => command.name !== body.name || command.type !== body.type);
    commands.push({ ...body, id: String(1000 + commands.length), version: '2', application_id: '123' });
    return Response.json(commands.at(-1));
  };
  const request = makeRequest('test-token', fetcher);
  const first = await registerCommands({ catalog, guild: '456', request, backup: async before => { assert.equal(before[0].name, 'other'); backups += 1; } });
  assert.deepEqual(first, { changed: catalog.length, verified: catalog.length });
  assert.deepEqual(commands[0], unknown);
  assert.deepEqual(commands[1], sameNameOtherType);
  backups = 0;
  calls.length = 0;
  const second = await registerCommands({ catalog, guild: '456', request, backup: async () => { backups += 1; } });
  assert.deepEqual(second, { changed: 0, verified: catalog.length });
  const withArgs = catalog.find(command => command.options?.length);
  assert.equal(equalCommand(withArgs, { ...withArgs, options: [{ ...withArgs.options[0], choices: [{ name: 'Restricted', value: 'restricted' }] }] }), false);
  assert.equal(equalCommand(withArgs, { ...withArgs, options: [{ ...withArgs.options[0], max_length: 1 }] }), false);
  assert.equal(equalCommand(withArgs, { ...withArgs, options: [{ ...withArgs.options[0], autocomplete: false, choices: [], name_localizations: null }] }), true);
  assert.equal(calls.filter(([method]) => method === 'POST').length, 0);
  const restricted = commands.find(command => command.name === catalog[0].name && command.type === 1);
  restricted.default_member_permissions = '0';
  restricted.nsfw = true;
  backups = 0;
  calls.length = 0;
  const repaired = await registerCommands({ catalog, guild: '456', request, backup: async () => { backups += 1; } });
  assert.deepEqual(repaired, { changed: 1, verified: catalog.length });
  assert.equal(calls.filter(([method]) => method === 'POST').length, 1);
  assert.equal(commands.find(command => command.name === catalog[0].name && command.type === 1).default_member_permissions, null);
  assert.equal(commands.find(command => command.name === catalog[0].name && command.type === 1).nsfw, false);
  assert.equal(equalCommand(catalog[0], { ...catalog[0], default_permission: false }), false);
  for (const restriction of [{ default_member_permissions: '0' }, { default_permission: false }]) {
    await assert.rejects(registerCommands({ catalog, guild: '456', backup: async () => {}, request: async (method, path) => {
      if (path === '/oauth2/applications/@me') return { id: '123' };
      if (method === 'POST') return {};
      return commands.map(command => command.name === catalog[0].name && command.type === 1 ? { ...command, ...restriction } : command);
    } }), /readback_mismatch/);
  }
  await assert.rejects(makeRequest('test-token', async () => new Response('{}', { status: 403 }))('GET', '/test'), /http_403/);
  await assert.rejects(makeRequest('test-token', async () => { throw new Error('private-secret'); })('GET', '/test'), error => error.message === 'request_failed');
  const dir = await mkdtemp(join(tmpdir(), 'discord-commands-test-'));
  try {
    const path = join(dir, 'backup.json');
    await saveBackup(path, [unknown]);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), [unknown]);
    await assert.rejects(saveBackup(path, []));
  } finally { await rm(dir, { recursive: true, force: true }); }
  console.log(`self-test passed; ${catalog.length} commands; no network`);
}

async function main() {
  const options = parseArgs(Bun.argv.slice(2));
  const catalog = validateCatalog(JSON.parse(await readFile(catalogPath, 'utf8')));
  if (options['--help']) {
    console.log('bun scripts/register_discord_commands.mjs --dry-run');
    console.log('bun scripts/register_discord_commands.mjs --apply --guild ID [--account NAME] [--config PATH] [--backup PATH]');
    console.log('bun scripts/register_discord_commands.mjs --self-test');
    return;
  }
  if (options['--self-test']) {
    if (options['--apply'] || options['--dry-run']) fail('self_test_must_run_alone');
    return selfTest(catalog);
  }
  if (options['--dry-run']) {
    console.log(`dry-run; ${catalog.length} commands; no network`);
    console.log(catalog.map(command => command.name).join(', '));
    return;
  }
  if (!options['--apply']) fail('choose_apply_or_dry_run');
  const guild = options['--guild'];
  if (!snowflake(guild)) fail('guild_required');
  const config = JSON.parse(await readFile(options['--config'] ?? join(homedir(), '.nullclaw/config.json'), 'utf8'));
  const account = selectAccount(config, options['--account']);
  if (account.guild_id && account.guild_id !== guild) fail('configured_guild_mismatch');
  const path = options['--backup'] ?? join(homedir(), '.nullclaw/backups/discord-commands', `${Date.now()}-${crypto.randomUUID()}.json`);
  const result = await registerCommands({ catalog, guild, request: makeRequest(account.token), backup: commands => saveBackup(path, commands) });
  console.log(`registration verified; ${result.verified} commands; ${result.changed} changed; backup saved`);
  console.log(catalog.map(command => command.name).join(', '));
}

try { await main(); } catch (error) {
  console.error(`registration failed; ${error instanceof RegistrationError ? error.code : 'local_operation_failed'}`);
  process.exitCode = 1;
}
