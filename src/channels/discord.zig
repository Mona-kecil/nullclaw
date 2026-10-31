const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const interaction_choices = @import("../interactions/choices.zig");
const websocket = @import("../websocket.zig");
const thread_stacks = @import("../thread_stacks.zig");

const Atomic = @import("../portable_atomic.zig").Atomic;

const log = std.log.scoped(.discord);

const PENDING_INTERACTION_TTL_MS: u64 = 60 * std.time.ms_per_min;

const PendingInteractionOption = struct {
    id: []const u8,
    label: []const u8,
    submit_text: []const u8,

    fn deinit(self: *const PendingInteractionOption, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

const PendingInteraction = struct {
    expires_at_ms: u64,
    chat_id: []const u8,
    options: []PendingInteractionOption,

    fn deinit(self: *const PendingInteraction, allocator: std.mem.Allocator) void {
        allocator.free(self.chat_id);
        for (self.options) |opt| opt.deinit(allocator);
        allocator.free(self.options);
    }
};

/// Discord channel — connects via WebSocket gateway, sends via REST API.
/// Splits messages at 2000 chars (Discord limit).
pub const DiscordChannel = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    guild_id: ?[]const u8,
    allow_bots: bool,
    account_id: []const u8 = "default",

    // Optional gateway fields (have defaults so existing init works)
    allow_from: []const []const u8 = &.{},
    require_mention: bool = false,
    intents: u32 = 37377, // GUILDS|GUILD_MESSAGES|MESSAGE_CONTENT|DIRECT_MESSAGES
    bus: ?*bus_mod.Bus = null,

    typing_mu: std_compat.sync.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,
    interaction_mu: std_compat.sync.Mutex = .{},
    pending_interactions: std.StringHashMapUnmanaged(PendingInteraction) = .empty,
    interaction_seq: Atomic(u64) = Atomic(u64).init(1),

    // Gateway state
    running: Atomic(bool) = Atomic(bool).init(false),
    sequence: Atomic(i64) = Atomic(i64).init(0),
    heartbeat_interval_ms: Atomic(u64) = Atomic(u64).init(0),
    heartbeat_stop: Atomic(bool) = Atomic(bool).init(false),
    last_gateway_activity_ms: Atomic(i64) = Atomic(i64).init(0),
    session_id: ?[]u8 = null,
    resume_gateway_url: ?[]u8 = null,
    bot_user_id: ?[]u8 = null,
    gateway_thread: ?std.Thread = null,
    ws_fd: Atomic(SocketFd) = Atomic(SocketFd).init(invalid_socket),
    /// Count of consecutive op-7 RECONNECT events without an intervening READY.
    /// Used to implement exponential backoff and RESUME→IDENTIFY fallback.
    /// Only accessed from gatewayLoop (single-threaded write path); no atomic needed.
    consecutive_reconnects: u32 = 0,

    const SocketFd = std_compat.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std_compat.net.invalidHandle(SocketFd),
        else => -1,
    };

    pub const MAX_MESSAGE_LEN: usize = 2000;
    pub const GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json";
    const TYPING_INTERVAL_NS: u64 = 8 * std.time.ns_per_s;
    const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms;
    /// Minimum stale-gateway grace window. The channel_manager checks health every 10s;
    /// allow at least 3 heartbeat intervals OR 90s before declaring the gateway dead.
    const GATEWAY_STALE_GRACE_MS: i64 = 90 * std.time.ms_per_s;
    /// After this many consecutive op-7 RECONNECT events without a successful READY,
    /// give up resuming and clear the session to force a fresh IDENTIFY.
    const MAX_RECONNECT_ATTEMPTS: u32 = 5;
    const InvalidSessionAction = enum {
        identify,
        resume_session,
    };

    const TypingTask = struct {
        channel: *DiscordChannel,
        channel_id: []const u8,
        stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        token: []const u8,
        guild_id: ?[]const u8,
        allow_bots: bool,
    ) DiscordChannel {
        return .{
            .allocator = allocator,
            .token = token,
            .guild_id = guild_id,
            .allow_bots = allow_bots,
        };
    }

    /// Initialize from a full DiscordConfig, passing all fields.
    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: @import("../config_types.zig").DiscordConfig) DiscordChannel {
        return .{
            .allocator = allocator,
            .token = cfg.token,
            .guild_id = cfg.guild_id,
            .allow_bots = cfg.allow_bots,
            .account_id = cfg.account_id,
            .allow_from = cfg.allow_from,
            .require_mention = cfg.require_mention,
            .intents = cfg.intents,
        };
    }

    pub fn channelName(_: *DiscordChannel) []const u8 {
        return "discord";
    }

    /// Build a Discord REST API URL for sending to a channel.
    pub fn sendUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/messages", .{channel_id});
        return w.buffered();
    }

    /// Build a Discord REST API URL for triggering typing in a channel.
    pub fn typingUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/typing", .{channel_id});
        return w.buffered();
    }

    pub fn editMessageUrl(buf: []u8, channel_id: []const u8, message_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/messages/{s}", .{ channel_id, message_id });
        return w.buffered();
    }

    fn interactionCallbackUrl(buf: []u8, interaction_id: []const u8, interaction_token: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/interactions/{s}/{s}/callback", .{ interaction_id, interaction_token });
        return w.buffered();
    }

    /// Extract bot user ID from a bot token.
    /// Discord bot tokens are base64(bot_user_id).random.hmac
    pub fn extractBotUserId(token: []const u8) ?[]const u8 {
        // Find the first '.'
        const dot_pos = std.mem.indexOf(u8, token, ".") orelse return null;
        return token[0..dot_pos];
    }

    pub fn healthCheck(self: *DiscordChannel) bool {
        return self.gatewayHealthyAt(std_compat.time.milliTimestamp());
    }

    pub fn setBus(self: *DiscordChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    // ── Gateway liveness helpers ──────────────────────────────────────────

    fn markGatewayActivityNow(self: *DiscordChannel) void {
        self.last_gateway_activity_ms.store(std_compat.time.milliTimestamp(), .release);
    }

    /// Returns true if the gateway appears healthy at the given wall-clock ms.
    /// Healthy conditions: not running, interval not yet received, or last activity
    /// within max(3×heartbeat_interval, GATEWAY_STALE_GRACE_MS).
    fn gatewayHealthyAt(self: *DiscordChannel, now_ms: i64) bool {
        if (!self.running.load(.acquire)) return true;

        const interval_ms = self.heartbeat_interval_ms.load(.acquire);
        if (interval_ms == 0) return true;

        const last_activity_ms = self.last_gateway_activity_ms.load(.acquire);
        if (last_activity_ms == 0 or now_ms <= last_activity_ms) return true;

        const heartbeat_window_ms: i64 = @as(i64, @intCast(interval_ms)) * 3;
        const stale_after_ms = @max(heartbeat_window_ms, GATEWAY_STALE_GRACE_MS);
        return (now_ms - last_activity_ms) <= stale_after_ms;
    }

    const ReconnectDecision = struct {
        attempt: u32,
        backoff_ms: u64,
        cleared_session: bool,
    };

    fn recordReconnectRequest(self: *DiscordChannel) ReconnectDecision {
        self.consecutive_reconnects += 1;
        const attempt = self.consecutive_reconnects;
        const shift = @min(attempt - 1, 6);
        const backoff_ms = @min(@as(u64, 1000) << @intCast(shift), 60_000);
        var cleared_session = false;

        if (attempt >= MAX_RECONNECT_ATTEMPTS) {
            self.clearSessionStateForIdentify();
            self.consecutive_reconnects = 0;
            cleared_session = true;
        }

        return .{
            .attempt = attempt,
            .backoff_ms = backoff_ms,
            .cleared_session = cleared_session,
        };
    }

    // ── Pure helper functions ─────────────────────────────────────────────

    /// Build IDENTIFY JSON payload (op=2).
    /// Example: {"op":2,"d":{"token":"Bot TOKEN","intents":37377,"properties":{"os":"linux","browser":"nullclaw","device":"nullclaw"}}}
    pub fn buildIdentifyJson(buf: []u8, token: []const u8, intents: u32) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print(
            "{{\"op\":2,\"d\":{{\"token\":\"Bot {s}\",\"intents\":{d},\"properties\":{{\"os\":\"linux\",\"browser\":\"nullclaw\",\"device\":\"nullclaw\"}}}}}}",
            .{ token, intents },
        );
        return w.buffered();
    }

    /// Build HEARTBEAT JSON payload (op=1).
    /// seq==0 → {"op":1,"d":null}, else {"op":1,"d":42}
    pub fn buildHeartbeatJson(buf: []u8, seq: i64) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        if (seq == 0) {
            try w.writeAll("{\"op\":1,\"d\":null}");
        } else {
            try w.print("{{\"op\":1,\"d\":{d}}}", .{seq});
        }
        return w.buffered();
    }

    /// Build RESUME JSON payload (op=6).
    /// {"op":6,"d":{"token":"Bot TOKEN","session_id":"SESSION","seq":42}}
    pub fn buildResumeJson(buf: []u8, token: []const u8, session_id: []const u8, seq: i64) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print(
            "{{\"op\":6,\"d\":{{\"token\":\"Bot {s}\",\"session_id\":\"{s}\",\"seq\":{d}}}}}",
            .{ token, session_id, seq },
        );
        return w.buffered();
    }

    /// Parse gateway host from wss:// URL.
    /// "wss://us-east1.gateway.discord.gg" -> "us-east1.gateway.discord.gg"
    /// "wss://gateway.discord.gg/?v=10&encoding=json" -> "gateway.discord.gg"
    /// Returns slice into wss_url (no allocation).
    pub fn parseGatewayHost(wss_url: []const u8) []const u8 {
        // Strip scheme prefix if present
        const no_scheme = if (std.mem.startsWith(u8, wss_url, "wss://"))
            wss_url[6..]
        else if (std.mem.startsWith(u8, wss_url, "ws://"))
            wss_url[5..]
        else
            wss_url;

        // Strip path (everything after first '/' or '?')
        const slash_pos = std.mem.indexOf(u8, no_scheme, "/");
        const query_pos = std.mem.indexOf(u8, no_scheme, "?");

        const end = blk: {
            if (slash_pos != null and query_pos != null) {
                break :blk @min(slash_pos.?, query_pos.?);
            } else if (slash_pos != null) {
                break :blk slash_pos.?;
            } else if (query_pos != null) {
                break :blk query_pos.?;
            } else {
                break :blk no_scheme.len;
            }
        };

        return no_scheme[0..end];
    }

    /// Check if bot is mentioned in message content.
    /// Returns true if "<@BOT_ID>" or "<@!BOT_ID>" appears in content.
    pub fn isMentioned(content: []const u8, bot_user_id: []const u8) bool {
        // Check for <@BOT_ID>
        var buf1: [64]u8 = undefined;
        const mention1 = std.fmt.bufPrint(&buf1, "<@{s}>", .{bot_user_id}) catch return false;
        if (std.mem.indexOf(u8, content, mention1) != null) return true;

        // Check for <@!BOT_ID>
        var buf2: [64]u8 = undefined;
        const mention2 = std.fmt.bufPrint(&buf2, "<@!{s}>", .{bot_user_id}) catch return false;
        if (std.mem.indexOf(u8, content, mention2) != null) return true;

        return false;
    }

    fn isReplyToBot(d_obj: std.json.ObjectMap, bot_user_id: []const u8) bool {
        if (bot_user_id.len == 0) return false;
        const message_type = d_obj.get("type") orelse return false;
        switch (message_type) {
            .integer => |value| if (value != 19) return false,
            else => return false,
        }
        const referenced_message = d_obj.get("referenced_message") orelse return false;
        const referenced_obj = switch (referenced_message) {
            .object => |o| o,
            else => return false,
        };
        const author_val = referenced_obj.get("author") orelse return false;
        const author_obj = switch (author_val) {
            .object => |o| o,
            else => return false,
        };
        const author_id_val = author_obj.get("id") orelse return false;
        const author_id = switch (author_id_val) {
            .string => |s| s,
            else => return false,
        };
        return std.mem.eql(u8, author_id, bot_user_id);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Discord channel via REST API.
    /// Splits at MAX_MESSAGE_LEN (2000 chars).
    pub fn sendMessage(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(channel_id, chunk);
        }
    }

    /// Send a Discord typing indicator (best-effort, errors ignored).
    pub fn sendTypingIndicator(self: *DiscordChannel, channel_id: []const u8) void {
        if (builtin.is_test) return;
        if (channel_id.len == 0) return;

        var url_buf: [256]u8 = undefined;
        const url = typingUrl(&url_buf, channel_id) catch return;

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        auth_writer.print("Authorization: Bot {s}", .{self.token}) catch return;
        const auth_header = auth_writer.buffered();

        // stopTyping joins this thread; optional network I/O must have a deadline.
        const resp = root.http_util.curlPostWithProxy(self.allocator, url, "{}", &.{auth_header}, null, "3") catch return;
        self.allocator.free(resp);
    }

    pub fn startTyping(self: *DiscordChannel, channel_id: []const u8) !void {
        if (!self.running.load(.acquire)) return;
        if (channel_id.len == 0) return;

        try self.stopTyping(channel_id);

        const key_copy = try self.allocator.dupe(u8, channel_id);
        errdefer self.allocator.free(key_copy);

        const task = try self.allocator.create(TypingTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .channel = self,
            .channel_id = key_copy,
        };

        task.thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE }, typingLoop, .{task});
        errdefer {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
    }

    pub fn stopTyping(self: *DiscordChannel, channel_id: []const u8) !void {
        var removed_key: ?[]u8 = null;
        var removed_task: ?*TypingTask = null;

        self.typing_mu.lock();
        if (self.typing_handles.fetchRemove(channel_id)) |entry| {
            removed_key = @constCast(entry.key);
            removed_task = entry.value;
        }
        self.typing_mu.unlock();

        if (removed_task) |task| {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
        }
        if (removed_key) |key| {
            self.allocator.free(key);
        }
    }

    fn stopAllTyping(self: *DiscordChannel) void {
        self.typing_mu.lock();
        var handles = self.typing_handles;
        self.typing_handles = .empty;
        self.typing_mu.unlock();

        var it = handles.iterator();
        while (it.next()) |entry| {
            const task = entry.value_ptr.*;
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        handles.deinit(self.allocator);
    }

    fn typingLoop(task: *TypingTask) void {
        while (!task.stop_requested.load(.acquire)) {
            task.channel.sendTypingIndicator(task.channel_id);
            var elapsed: u64 = 0;
            while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
                std_compat.thread.sleep(TYPING_SLEEP_STEP_NS);
                elapsed += TYPING_SLEEP_STEP_NS;
            }
        }
    }

    fn sendChunk(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        // Build JSON body: {"content":"..."}
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        try body_list.appendSlice(self.allocator, "}");

        // Build auth header value: "Authorization: Bot <token>"
        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, url, body_list.items, &.{auth_header}, null) catch |err| {
            log.err("Discord API POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        self.allocator.free(resp);
    }

    fn sendJsonMethod(self: *DiscordChannel, method: []const u8, url: []const u8, body: []const u8) !void {
        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const http_method: std.http.Method = if (std.mem.eql(u8, method, "PATCH")) .PATCH else .POST;
        const resp = root.http_util.httpRequest(self.allocator, http_method, url, body, &.{auth_writer.buffered()}, "application/json", null) catch return error.DiscordApiError;
        self.allocator.free(resp);
    }

    fn nextInteractionToken(self: *DiscordChannel) ![]u8 {
        const seq = self.interaction_seq.fetchAdd(1, .monotonic) + 1;
        var buf: [32]u8 = undefined;
        const token = try std.fmt.bufPrint(&buf, "{x}", .{seq});
        return self.allocator.dupe(u8, token);
    }

    fn buildChoicesDirectiveFromPayload(
        self: *DiscordChannel,
        choices: []const root.Channel.OutboundChoice,
    ) !interaction_choices.ChoicesDirective {
        if (choices.len < interaction_choices.MIN_OPTIONS or choices.len > interaction_choices.MAX_OPTIONS) {
            return error.InvalidChoices;
        }

        var options = try self.allocator.alloc(interaction_choices.ChoiceOption, choices.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }

        for (choices, 0..) |choice, i| {
            options[i] = .{
                .id = try self.allocator.dupe(u8, choice.id),
                .label = try self.allocator.dupe(u8, choice.label),
                .submit_text = try self.allocator.dupe(u8, choice.submit_text),
            };
            built += 1;
        }

        return .{
            .version = 1,
            .options = options,
        };
    }

    fn buildComponentsJson(
        self: *DiscordChannel,
        directive: interaction_choices.ChoicesDirective,
        token: []const u8,
    ) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);

        try out.appendSlice(self.allocator, "[");
        var row_start: usize = 0;
        while (row_start < directive.options.len) {
            if (row_start > 0) try out.appendSlice(self.allocator, ",");
            try out.appendSlice(self.allocator, "{\"type\":1,\"components\":[");

            const row_end = @min(row_start + 5, directive.options.len);
            for (directive.options[row_start..row_end], row_start..) |opt, idx| {
                if (idx > row_start) try out.appendSlice(self.allocator, ",");
                var cb_buf: [100]u8 = undefined;
                const custom_id = try interaction_choices.formatChoiceCallbackData(&cb_buf, token, opt.id, 100);
                try out.appendSlice(self.allocator, "{\"type\":2,\"style\":1,\"label\":");
                try root.json_util.appendJsonString(&out, self.allocator, opt.label);
                try out.appendSlice(self.allocator, ",\"custom_id\":");
                try root.json_util.appendJsonString(&out, self.allocator, custom_id);
                try out.appendSlice(self.allocator, "}");
            }
            try out.appendSlice(self.allocator, "]}");
            row_start = row_end;
        }
        try out.appendSlice(self.allocator, "]");
        return try out.toOwnedSlice(self.allocator);
    }

    fn registerPendingInteraction(
        self: *DiscordChannel,
        token: []const u8,
        chat_id: []const u8,
        directive: interaction_choices.ChoicesDirective,
    ) !void {
        var options = try self.allocator.alloc(PendingInteractionOption, directive.options.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }

        for (directive.options, 0..) |opt, i| {
            options[i] = .{
                .id = try self.allocator.dupe(u8, opt.id),
                .label = try self.allocator.dupe(u8, opt.label),
                .submit_text = try self.allocator.dupe(u8, opt.submit_text),
            };
            built += 1;
        }

        const key = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(key);
        const chat_copy = try self.allocator.dupe(u8, chat_id);
        errdefer self.allocator.free(chat_copy);

        const now_ms = std_compat.time.milliTimestamp();
        if (now_ms < 0) return error.InvalidTimestamp;
        self.pruneExpiredInteractions();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();
        try self.pending_interactions.put(self.allocator, key, .{
            .expires_at_ms = @as(u64, @intCast(now_ms)) + PENDING_INTERACTION_TTL_MS,
            .chat_id = chat_copy,
            .options = options,
        });
    }

    fn pruneExpiredInteractions(self: *DiscordChannel) void {
        const now_ms: i64 = std_compat.time.milliTimestamp();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        var it = self.pending_interactions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at_ms <= @as(u64, @intCast(now_ms))) {
                const key = entry.key_ptr.*;
                if (self.pending_interactions.fetchRemove(key)) |kv| {
                    self.allocator.free(@constCast(kv.key));
                    kv.value.deinit(self.allocator);
                }
            }
        }
    }

    const CallbackSelection = union(enum) {
        ok: []u8,
        not_found,
        expired,
        invalid_chat,
        invalid_option,
    };

    fn consumeCallbackSelection(
        self: *DiscordChannel,
        allocator: std.mem.Allocator,
        token: []const u8,
        option_id: []const u8,
        chat_id: []const u8,
    ) !CallbackSelection {
        self.pruneExpiredInteractions();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        const pending_ptr = self.pending_interactions.getPtr(token) orelse return .not_found;
        if (pending_ptr.expires_at_ms <= @as(u64, @intCast(std_compat.time.milliTimestamp()))) {
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                self.allocator.free(@constCast(kv.key));
                kv.value.deinit(self.allocator);
            }
            return .expired;
        }
        if (!std.mem.eql(u8, pending_ptr.chat_id, chat_id)) return .invalid_chat;

        for (pending_ptr.options) |opt| {
            if (!std.mem.eql(u8, opt.id, option_id)) continue;
            const submit_text = try allocator.dupe(u8, opt.submit_text);
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                self.allocator.free(@constCast(kv.key));
                kv.value.deinit(self.allocator);
            }
            return .{ .ok = submit_text };
        }
        return .invalid_option;
    }

    fn deinitPendingInteractions(self: *DiscordChannel) void {
        self.interaction_mu.lock();
        var pending = self.pending_interactions;
        self.pending_interactions = .empty;
        self.interaction_mu.unlock();

        var it = pending.iterator();
        while (it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            entry.value_ptr.deinit(self.allocator);
        }
        pending.deinit(self.allocator);
    }

    fn sendRichMessage(self: *DiscordChannel, channel_id: []const u8, payload: root.Channel.OutboundPayload) !void {
        if (payload.attachments.len > 0) return error.NotSupported;
        if (payload.choices.len == 0) return self.sendMessage(channel_id, payload.text);

        var directive = try self.buildChoicesDirectiveFromPayload(payload.choices);
        defer directive.deinit(self.allocator);

        const token = try self.nextInteractionToken();
        defer self.allocator.free(token);
        const components_json = try self.buildComponentsJson(directive, token);
        defer self.allocator.free(components_json);

        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body, self.allocator, payload.text);
        try body.appendSlice(self.allocator, ",\"components\":");
        try body.appendSlice(self.allocator, components_json);
        try body.appendSlice(self.allocator, "}");

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, url, body.items, &.{auth_header}, null) catch |err| {
            log.err("Discord API rich POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        defer self.allocator.free(resp);

        try self.registerPendingInteraction(token, channel_id, directive);
    }

    fn editRichMessage(self: *DiscordChannel, edit: root.Channel.MessageEdit) !void {
        if (edit.payload.attachments.len > 0) return error.NotSupported;

        var components_json: ?[]u8 = null;
        defer if (components_json) |json| self.allocator.free(json);

        if (edit.payload.choices.len > 0) {
            var directive = try self.buildChoicesDirectiveFromPayload(edit.payload.choices);
            defer directive.deinit(self.allocator);

            const token = try self.nextInteractionToken();
            defer self.allocator.free(token);
            components_json = try self.buildComponentsJson(directive, token);
            try self.registerPendingInteraction(token, edit.target, directive);
        }

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body, self.allocator, edit.payload.text);
        if (components_json) |json| {
            try body.appendSlice(self.allocator, ",\"components\":");
            try body.appendSlice(self.allocator, json);
        } else {
            try body.appendSlice(self.allocator, ",\"components\":[]");
        }
        try body.appendSlice(self.allocator, "}");

        var url_buf: [256]u8 = undefined;
        const url = try editMessageUrl(&url_buf, edit.target, edit.message_id);
        try self.sendJsonMethod("PATCH", url, body.items);
    }

    fn answerInteraction(self: *DiscordChannel, interaction_id: []const u8, interaction_token: []const u8, message: ?[]const u8) void {
        if (builtin.is_test) return;

        var url_buf: [512]u8 = undefined;
        const url = interactionCallbackUrl(&url_buf, interaction_id, interaction_token) catch return;

        const body = if (message) |msg|
            std.fmt.allocPrint(self.allocator, "{{\"type\":4,\"data\":{{\"content\":{f},\"flags\":64}}}}", .{std.json.fmt(msg, .{})})
        else
            self.allocator.dupe(u8, "{\"type\":6}");
        const owned_body = body catch return;
        defer self.allocator.free(owned_body);

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, url, owned_body, &.{}, null) catch return;
        self.allocator.free(resp);
    }

    // ── Gateway ──────────────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.markGatewayActivityNow();
        self.running.store(true, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.heartbeat_stop.store(true, .release);
        self.stopAllTyping();
        self.deinitPendingInteractions();
        // Shut down the socket to unblock a blocking readv in the gateway thread.
        // close() on a remote TCP socket does NOT interrupt a blocked readv in another
        // thread on POSIX/macOS — the kernel holds its own file-description reference
        // for the blocked reader.  shutdown(SHUT_RDWR) explicitly delivers EOF to the
        // blocked reader, causing it to return 0 (EndOfStream → ConnectionClosed).
        // NOTE: No unit test for this path — requires a live remote TCP connection and
        // concurrent thread; covered by manual integration testing against a live gateway.
        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            (std_compat.net.Stream{ .handle = fd }).shutdown(.both) catch {};
        }
        if (self.gateway_thread) |t| {
            t.join();
            self.gateway_thread = null;
        }
        // Free session state
        if (self.session_id) |s| {
            self.allocator.free(s);
            self.session_id = null;
        }
        if (self.resume_gateway_url) |u| {
            self.allocator.free(u);
            self.resume_gateway_url = null;
        }
        if (self.bot_user_id) |u| {
            self.allocator.free(u);
            self.bot_user_id = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendRichMessage(target, payload);
    }

    fn vtableEditMessage(ptr: *anyopaque, edit: root.Channel.MessageEdit) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.editRichMessage(edit);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .sendRich = &vtableSendRich,
        .editMessage = &vtableEditMessage,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
    };

    pub fn channel(self: *DiscordChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Gateway loop ─────────────────────────────────────────────────

    fn gatewayLoop(self: *DiscordChannel) void {
        while (self.running.load(.acquire)) {
            var backoff_ms: u64 = 5000;
            self.runGatewayOnce() catch |err| switch (err) {
                error.ShouldReconnect => {
                    // OP7 RECONNECT is a normal control signal from Discord.
                    // Use exponential backoff to avoid rate-limiting reconnect storms:
                    // attempt 1→1s, 2→2s, 3→4s, 4→8s, 5→16s, 6→32s, 7+→60s.
                    const reconnect = self.recordReconnectRequest();
                    backoff_ms = reconnect.backoff_ms;
                    log.info("Discord gateway reconnect requested by server (attempt {d}, backoff {d}ms)", .{ reconnect.attempt, reconnect.backoff_ms });
                    if (reconnect.cleared_session) log.warn(
                        "Discord: {d} consecutive reconnects without READY; clearing session for fresh IDENTIFY",
                        .{reconnect.attempt},
                    );
                },
                else => {
                    self.consecutive_reconnects = 0;
                    log.warn("Discord gateway error: {}", .{err});
                },
            };
            if (!self.running.load(.acquire)) break;
            // Backoff between reconnects (interruptible).
            var slept: u64 = 0;
            while (slept < backoff_ms and self.running.load(.acquire)) {
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
                slept += 100;
            }
        }
    }

    fn runGatewayOnce(self: *DiscordChannel) !void {
        // Refresh the watchdog baseline before DNS/TCP/TLS. A restart should get a
        // full stale-gateway grace window instead of inheriting the old dead socket's
        // last activity timestamp.
        self.markGatewayActivityNow();

        // Determine host
        const default_host = "gateway.discord.gg";
        const host: []const u8 = if (self.resume_gateway_url) |u| parseGatewayHost(u) else default_host;

        // Phase 1: DNS + TCP only.
        // Storing ws_fd before TLS init lets vtableStop interrupt a stalled TLS handshake
        // via shutdown(.both), which delivers EOF to the blocked readv immediately.
        const ws_stream = websocket.WsClient.connectTcp(self.allocator, host, 443) catch |err| {
            // TCP failed — clear stale resume URL so next attempt uses gateway.discord.gg.
            if (self.resume_gateway_url) |u| {
                self.allocator.free(u);
                self.resume_gateway_url = null;
            }
            return err;
        };
        // Store fd now so vtableStop can interrupt even during the TLS handshake below.
        self.ws_fd.store(ws_stream.handle, .release);

        // Phase 2: TLS init + WebSocket handshake (interruptible via vtableStop shutdown).
        var ws = websocket.WsClient.connectFromStream(
            self.allocator,
            ws_stream,
            host,
            "/?v=10&encoding=json",
            &.{},
        ) catch |err| {
            // connectFromStream closed ws_stream on failure; clear the now-invalid fd.
            self.ws_fd.store(invalid_socket, .release);
            // Clear stale resume URL same as TCP failure path above.
            if (self.resume_gateway_url) |u| {
                self.allocator.free(u);
                self.resume_gateway_url = null;
            }
            return err;
        };
        // ws now owns ws_stream; the defer block below handles ws_fd reset + ws.deinit().

        // Start heartbeat thread — on failure, clean up ws manually (no errdefer to avoid
        // double-deinit with the defer block below once spawn succeeds).
        self.heartbeat_stop.store(false, .release);
        self.heartbeat_interval_ms.store(0, .release);
        const hbt = std.Thread.spawn(.{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE }, heartbeatLoop, .{ self, &ws }) catch |err| {
            ws.deinit();
            return err;
        };
        defer {
            self.heartbeat_stop.store(true, .release);
            hbt.join();
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }

        // Wait for HELLO (first message)
        const hello_text = try ws.readTextMessage() orelse return error.ConnectionClosed;
        defer self.allocator.free(hello_text);
        try self.handleHello(&ws, hello_text);
        // Record activity after HELLO so the health watchdog has a baseline timestamp.
        self.markGatewayActivityNow();

        // IDENTIFY or RESUME
        if (self.session_id != null) {
            try self.sendResumePayload(&ws);
        } else {
            self.sequence.store(0, .release);
            try self.sendIdentifyPayload(&ws);
        }

        // Main read loop
        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch |err| {
                log.warn("Discord gateway read failed: {}", .{err});
                break;
            };
            const text = maybe_text orelse break;
            defer self.allocator.free(text);
            self.markGatewayActivityNow();
            self.handleGatewayMessage(&ws, text) catch |err| {
                if (err == error.ShouldReconnect) return err;
                log.err("Discord gateway msg error: {}", .{err});
            };
        }
    }

    // ── Heartbeat thread ─────────────────────────────────────────────

    fn heartbeatLoop(self: *DiscordChannel, ws: *websocket.WsClient) void {
        // Wait for interval to be set
        while (!self.heartbeat_stop.load(.acquire) and self.heartbeat_interval_ms.load(.acquire) == 0) {
            std_compat.thread.sleep(10 * std.time.ns_per_ms);
        }
        while (!self.heartbeat_stop.load(.acquire)) {
            const interval_ms = self.heartbeat_interval_ms.load(.acquire);
            var elapsed: u64 = 0;
            while (elapsed < interval_ms) {
                if (self.heartbeat_stop.load(.acquire)) return;
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
                elapsed += 100;
            }
            if (self.heartbeat_stop.load(.acquire)) return;

            const seq = self.sequence.load(.acquire);
            var hb_buf: [64]u8 = undefined;
            const hb_json = buildHeartbeatJson(&hb_buf, seq) catch continue;
            ws.writeText(hb_json) catch |err| {
                log.warn("Discord heartbeat failed: {}", .{err});
            };
        }
    }

    // ── Message handlers ─────────────────────────────────────────────

    /// Parse HELLO payload and store heartbeat interval.
    fn handleHello(self: *DiscordChannel, _: *websocket.WsClient, text: []const u8) !void {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, text, .{});
        defer parsed.deinit();

        const root_val = parsed.value;
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse return;
        switch (d_val) {
            .object => |d_obj| {
                const hb_val = d_obj.get("heartbeat_interval") orelse return;
                switch (hb_val) {
                    .integer => |ms| {
                        if (ms > 0) {
                            self.heartbeat_interval_ms.store(@intCast(ms), .release);
                        }
                    },
                    .float => |ms| {
                        if (ms > 0) {
                            self.heartbeat_interval_ms.store(@intFromFloat(ms), .release);
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    /// Handle a gateway message, switching on op code.
    fn handleGatewayMessage(self: *DiscordChannel, ws: *websocket.WsClient, text: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, text, .{}) catch |err| {
            log.warn("Discord: failed to parse gateway message: {}", .{err});
            return;
        };
        defer parsed.deinit();

        const root_val = parsed.value;
        if (root_val != .object) {
            log.warn("Discord: gateway message root is not an object", .{});
            return;
        }

        // Get op code
        const op_val = root_val.object.get("op") orelse {
            log.warn("Discord: gateway message missing 'op' field", .{});
            return;
        };
        const op: i64 = switch (op_val) {
            .integer => |i| i,
            else => {
                log.warn("Discord: gateway 'op' is not an integer", .{});
                return;
            },
        };

        switch (op) {
            10 => { // HELLO
                self.handleHello(ws, text) catch |err| {
                    log.warn("Discord: handleHello error: {}", .{err});
                };
            },
            0 => { // DISPATCH
                // Update sequence from "s" field
                if (root_val.object.get("s")) |s_val| {
                    switch (s_val) {
                        .integer => |s| {
                            // Sequence comes from the active gateway session and is ordered.
                            // Always overwrite to avoid stale seq after a fresh IDENTIFY.
                            self.sequence.store(s, .release);
                        },
                        else => {},
                    }
                }

                // Get event type "t"
                const t_val = root_val.object.get("t") orelse return;
                const event_type: []const u8 = switch (t_val) {
                    .string => |s| s,
                    else => return,
                };

                if (std.mem.eql(u8, event_type, "READY")) {
                    self.handleReady(root_val) catch |err| {
                        log.warn("Discord: handleReady error: {}", .{err});
                    };
                } else if (std.mem.eql(u8, event_type, "MESSAGE_CREATE")) {
                    self.handleMessageCreate(root_val) catch |err| {
                        log.warn("Discord: handleMessageCreate error: {}", .{err});
                    };
                } else if (std.mem.eql(u8, event_type, "INTERACTION_CREATE")) {
                    self.handleInteractionCreate(root_val) catch |err| {
                        log.warn("Discord: handleInteractionCreate error: {}", .{err});
                    };
                }
            },
            1 => { // HEARTBEAT — server requests immediate heartbeat
                const seq = self.sequence.load(.acquire);
                var hb_buf: [64]u8 = undefined;
                const hb_json = buildHeartbeatJson(&hb_buf, seq) catch return;
                ws.writeText(hb_json) catch |err| {
                    log.warn("Discord: immediate heartbeat failed: {}", .{err});
                };
            },
            11 => { // HEARTBEAT_ACK
                // No-op — heartbeat acknowledged
            },
            7 => { // RECONNECT
                log.info("Discord: server requested reconnect", .{});
                return error.ShouldReconnect;
            },
            9 => { // INVALID_SESSION
                // Check if resumable (d field)
                const d_val = root_val.object.get("d");
                const resumable = if (d_val) |d| switch (d) {
                    .bool => |b| b,
                    else => false,
                } else false;
                switch (self.resolveInvalidSessionAction(resumable)) {
                    .resume_session => {
                        self.sendResumePayload(ws) catch |err| {
                            log.warn("Discord: resume after INVALID_SESSION failed: {}", .{err});
                            return error.ShouldReconnect;
                        };
                    },
                    .identify => {
                        self.sendIdentifyPayload(ws) catch |err| {
                            log.warn("Discord: re-identify after INVALID_SESSION failed: {}", .{err});
                            return error.ShouldReconnect;
                        };
                    },
                }
            },
            else => {
                log.warn("Discord: unhandled gateway op={d}", .{op});
            },
        }
    }

    fn clearSessionStateForIdentify(self: *DiscordChannel) void {
        if (self.session_id) |s| {
            self.allocator.free(s);
            self.session_id = null;
        }
        if (self.resume_gateway_url) |u| {
            self.allocator.free(u);
            self.resume_gateway_url = null;
        }
        self.sequence.store(0, .release);
    }

    fn resolveInvalidSessionAction(self: *DiscordChannel, resumable: bool) InvalidSessionAction {
        if (resumable and self.session_id != null) {
            return .resume_session;
        }
        // Either explicitly non-resumable OR resumable but local session state is absent.
        // In both cases fall back to a clean IDENTIFY path.
        self.clearSessionStateForIdentify();
        return .identify;
    }

    /// Handle READY event: extract session_id, resume_gateway_url, bot_user_id.
    fn handleReady(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse {
            log.warn("Discord READY: missing 'd' field", .{});
            return;
        };
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => {
                log.warn("Discord READY: 'd' is not an object", .{});
                return;
            },
        };

        // Extract session_id
        if (d_obj.get("session_id")) |sid_val| {
            switch (sid_val) {
                .string => |s| {
                    if (self.session_id) |old| self.allocator.free(old);
                    self.session_id = try self.allocator.dupe(u8, s);
                },
                else => {},
            }
        }

        // Extract resume_gateway_url
        if (d_obj.get("resume_gateway_url")) |rgu_val| {
            switch (rgu_val) {
                .string => |s| {
                    if (self.resume_gateway_url) |old| self.allocator.free(old);
                    self.resume_gateway_url = try self.allocator.dupe(u8, s);
                },
                else => {},
            }
        }

        // Extract bot user ID from d.user.id
        if (d_obj.get("user")) |user_val| {
            switch (user_val) {
                .object => |user_obj| {
                    if (user_obj.get("id")) |id_val| {
                        switch (id_val) {
                            .string => |s| {
                                if (self.bot_user_id) |old| self.allocator.free(old);
                                self.bot_user_id = try self.allocator.dupe(u8, s);
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }

        log.info("Discord READY: session_id={s}", .{self.session_id orelse "<none>"});
        // A successful READY means we have a live session — reset the reconnect counter
        // so the next op-7 (if any) gets a fresh exponential backoff window.
        self.consecutive_reconnects = 0;
    }

    /// Handle MESSAGE_CREATE event and publish to bus if filters pass.
    fn handleMessageCreate(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse {
            log.warn("Discord MESSAGE_CREATE: missing 'd' field", .{});
            return;
        };
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'd' is not an object", .{});
                return;
            },
        };

        // Extract channel_id
        const channel_id: []const u8 = if (d_obj.get("channel_id")) |v| switch (v) {
            .string => |s| s,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'channel_id' is not a string", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'channel_id'", .{});
            return;
        };

        // Extract content
        const content: []const u8 = if (d_obj.get("content")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "";

        // Extract guild_id (optional — absent for DMs)
        const guild_id: ?[]const u8 = if (d_obj.get("guild_id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author object
        const author_obj = if (d_obj.get("author")) |v| switch (v) {
            .object => |o| o,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'author' is not an object", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'author'", .{});
            return;
        };

        // Extract author.id
        const author_id: []const u8 = if (author_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'author.id' is not a string", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'author.id'", .{});
            return;
        };

        // Extract author.username
        const author_username: ?[]const u8 = if (author_obj.get("username")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author.global_name (Discord display name)
        const author_display_name: ?[]const u8 = if (author_obj.get("global_name")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author.bot (defaults to false if absent)
        const author_is_bot: bool = if (author_obj.get("bot")) |v| switch (v) {
            .bool => |b| b,
            else => false,
        } else false;

        // Filter 1: bot author
        if (author_is_bot and !self.allow_bots) {
            return;
        }

        // Filter 2: require_mention for guild (non-DM) messages
        if (self.require_mention and guild_id != null) {
            const bot_uid = self.bot_user_id orelse "";
            if (!isMentioned(content, bot_uid) and !isReplyToBot(d_obj, bot_uid)) {
                return;
            }
        }

        // Filter 3: allow_from allowlist
        if (!root.isAllowedScoped("discord channel", self.allow_from, author_id)) {
            return;
        }

        // Process attachments (if any)
        var content_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer content_buf.deinit(self.allocator);

        if (content.len > 0) {
            content_buf.appendSlice(self.allocator, content) catch {};
        }

        if (d_obj.get("attachments")) |att_val| {
            if (att_val == .array) {
                const rand = std_compat.crypto.random;
                for (att_val.array.items) |att_item| {
                    if (att_item == .object) {
                        if (att_item.object.get("url")) |url_val| {
                            if (url_val == .string) {
                                const attach_url = url_val.string;

                                // Download it
                                if (root.http_util.curlGet(self.allocator, attach_url, &.{}, "30")) |img_data| {
                                    defer self.allocator.free(img_data);

                                    // Make temp file
                                    const rand_id = rand.int(u64);
                                    var path_buf: [1024]u8 = undefined;
                                    const local_path = std.fmt.bufPrint(&path_buf, "/tmp/discord_{x}.dat", .{rand_id}) catch continue;

                                    if (std_compat.fs.createFileAbsolute(local_path, .{ .read = false })) |file| {
                                        file.writeAll(img_data) catch {
                                            file.close();
                                            continue;
                                        };
                                        file.close();

                                        if (content_buf.items.len > 0) content_buf.appendSlice(self.allocator, "\n") catch {};
                                        content_buf.appendSlice(self.allocator, "[IMAGE:") catch {};
                                        content_buf.appendSlice(self.allocator, local_path) catch {};
                                        content_buf.appendSlice(self.allocator, "]") catch {};
                                    } else |_| {}
                                } else |err| {
                                    log.warn("Discord: failed to download attachment: {}", .{err});
                                }
                            }
                        }
                    }
                }
            }
        }

        const final_content = content_buf.toOwnedSlice(self.allocator) catch blk: {
            break :blk try self.allocator.dupe(u8, content);
        };
        defer self.allocator.free(final_content);

        // Build account-aware session key fallback to prevent cross-account bleed
        // when route resolution is unavailable.
        const session_key = if (guild_id == null)
            try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, author_id })
        else
            try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
        defer self.allocator.free(session_key);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(self.allocator);
        var metadata_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &metadata_buf);
        const mw = &metadata_writer.writer;
        try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
        try mw.writeAll(",\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        if (guild_id) |gid| {
            try mw.writeAll(",\"guild_id\":");
            try root.appendJsonStringW(mw, gid);
        }
        if (author_username) |uname| {
            try mw.writeAll(",\"sender_username\":");
            try root.appendJsonStringW(mw, uname);
        }
        if (author_display_name) |dname| {
            try mw.writeAll(",\"sender_display_name\":");
            try root.appendJsonStringW(mw, dname);
        }
        try mw.writeByte('}');
        metadata_buf = metadata_writer.toArrayList();

        var msg = try bus_mod.makeInboundFull(
            self.allocator,
            "discord",
            author_id,
            channel_id,
            final_content,
            session_key,
            &.{},
            metadata_buf.items,
        );
        msg.trusted_sender = true;

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("Discord: failed to publish inbound message: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            // No bus configured — free the message
            msg.deinit(self.allocator);
        }
    }

    const NativeOptionSpec = struct {
        type: u8,
        name: []const u8,
        description: []const u8,
        required: bool = false,
        max_length: usize,
    };
    const NativeCommandSpec = struct {
        type: u8,
        name: []const u8,
        description: []const u8,
        default_member_permissions: ?[]const u8,
        nsfw: bool,
        options: []const NativeOptionSpec = &.{},
    };
    const NativeCallback = struct {
        ctx: *anyopaque,
        send: *const fn (*anyopaque, []const u8, []const u8, []const u8) anyerror!void,
    };

    fn loadCommandCatalog(allocator: std.mem.Allocator) !std.json.Parsed([]NativeCommandSpec) {
        const parsed = try std.json.parseFromSlice([]NativeCommandSpec, allocator, @embedFile("discord_commands.json"), .{});
        errdefer parsed.deinit();
        for (parsed.value, 0..) |command, i| {
            if (command.type != 1 or command.name.len == 0 or command.description.len == 0 or command.default_member_permissions != null or command.nsfw or command.options.len > 1) return error.InvalidCatalog;
            for (parsed.value[0..i]) |other| {
                if (std.mem.eql(u8, command.name, other.name)) return error.InvalidCatalog;
            }
            for (command.options) |option| {
                if (option.type != 3 or !std.mem.eql(u8, option.name, "args") or option.required or option.max_length != MAX_MESSAGE_LEN or option.description.len == 0) return error.InvalidCatalog;
            }
        }
        return parsed;
    }

    fn nativeString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
        const value = object.get(key) orelse return error.InvalidInteraction;
        if (value != .string or value.string.len == 0) return error.InvalidInteraction;
        return value.string;
    }

    fn nativeUrlPart(value: []const u8) bool {
        return value.len > 0 and value.len <= 512;
    }

    fn encodeNativeSegment(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
        if (!nativeUrlPart(value)) return error.InvalidInteraction;
        var encoded: std.ArrayListUnmanaged(u8) = .empty;
        errdefer encoded.deinit(allocator);
        const hex = "0123456789ABCDEF";
        for (value) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
                try encoded.append(allocator, c);
            } else {
                try encoded.appendSlice(allocator, &.{ '%', hex[c >> 4], hex[c & 15] });
            }
        }
        return encoded.toOwnedSlice(allocator);
    }

    fn prepareApplicationCommand(self: *DiscordChannel, d: std.json.ObjectMap) !bus_mod.InboundMessage {
        const channel_id = try nativeString(d, "channel_id");
        const guild_id: ?[]const u8 = if (d.contains("guild_id")) try nativeString(d, "guild_id") else null;
        if (self.guild_id) |configured| {
            if (guild_id == null or !std.mem.eql(u8, configured, guild_id.?)) return error.Unauthorized;
        }
        const user = if (guild_id != null) blk: {
            const member = d.get("member") orelse return error.InvalidInteraction;
            if (member != .object) return error.InvalidInteraction;
            break :blk member.object.get("user") orelse return error.InvalidInteraction;
        } else blk: {
            if (d.contains("member")) return error.InvalidInteraction;
            break :blk d.get("user") orelse return error.InvalidInteraction;
        };
        if (user != .object) return error.InvalidInteraction;
        const user_id = try nativeString(user.object, "id");
        if (user.object.get("bot")) |bot| {
            if (bot != .bool) return error.InvalidInteraction;
            if (bot.bool) return error.Unauthorized;
        }
        if (!root.isAllowedScoped("discord channel", self.allow_from, user_id)) return error.Unauthorized;
        const username: ?[]const u8 = if (user.object.get("username")) |v| switch (v) {
            .string => v.string,
            .null => null,
            else => return error.InvalidInteraction,
        } else null;
        const display_name: ?[]const u8 = if (user.object.get("global_name")) |v| switch (v) {
            .string => v.string,
            .null => null,
            else => return error.InvalidInteraction,
        } else null;
        const data = d.get("data") orelse return error.InvalidInteraction;
        if (data != .object) return error.InvalidInteraction;
        if (data.object.get("type")) |kind| {
            if (kind != .integer or kind.integer != 1) return error.InvalidInteraction;
        }
        const name = try nativeString(data.object, "name");
        const catalog = try loadCommandCatalog(self.allocator);
        defer catalog.deinit();
        const spec = for (catalog.value) |command| {
            if (std.mem.eql(u8, command.name, name)) break command;
        } else return error.InvalidInteraction;
        var args: []const u8 = "";
        if (data.object.get("options")) |options| {
            if (options != .array or options.array.items.len > 1) return error.InvalidInteraction;
            if (options.array.items.len == 1) {
                if (spec.options.len != 1) return error.InvalidInteraction;
                const option = options.array.items[0];
                if (option != .object or option.object.count() != 3) return error.InvalidInteraction;
                const option_type = option.object.get("type") orelse return error.InvalidInteraction;
                if (option_type != .integer or option_type.integer != 3) return error.InvalidInteraction;
                if (!std.mem.eql(u8, try nativeString(option.object, "name"), "args")) return error.InvalidInteraction;
                const value = option.object.get("value") orelse return error.InvalidInteraction;
                if (value != .string or value.string.len > MAX_MESSAGE_LEN or std.mem.indexOfScalar(u8, value.string, 0) != null) return error.InvalidInteraction;
                args = std.mem.trim(u8, value.string, " \t\r\n");
            }
        }
        const text = if (args.len == 0)
            try std.fmt.allocPrint(self.allocator, "/{s}", .{name})
        else
            try std.fmt.allocPrint(self.allocator, "/{s} {s}", .{ name, args });
        defer self.allocator.free(text);
        const session_key = if (guild_id == null)
            try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, user_id })
        else
            try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
        defer self.allocator.free(session_key);
        const metadata = try std.json.Stringify.valueAlloc(self.allocator, .{
            .is_dm = guild_id == null,
            .account_id = self.account_id,
            .interaction = "application_command",
            .guild_id = guild_id,
            .sender_username = username,
            .sender_display_name = display_name,
        }, .{ .emit_null_optional_fields = false });
        defer self.allocator.free(metadata);
        return bus_mod.makeInboundFull(self.allocator, "discord", user_id, channel_id, text, session_key, &.{}, metadata);
    }

    fn nativeReceipt(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{{\"type\":4,\"data\":{{\"content\":{f},\"flags\":64}}}}", .{std.json.fmt(text, .{})});
    }

    fn handleApplicationCommand(self: *DiscordChannel, data: std.json.Value, callback: NativeCallback) !void {
        const d = data.object;
        const id = try nativeString(d, "id");
        const token = try nativeString(d, "token");
        if (!nativeUrlPart(id) or !nativeUrlPart(token)) return error.InvalidInteraction;
        const b = self.bus orelse return error.NoBus;
        b.inbound.mutex.lock();
        const closed = b.inbound.closed;
        b.inbound.mutex.unlock();
        if (closed) return error.Closed;
        const msg = self.prepareApplicationCommand(d) catch |err| switch (err) {
            error.InvalidInteraction, error.Unauthorized => {
                const rejected = try nativeReceipt(self.allocator, "This command is unavailable.");
                defer self.allocator.free(rejected);
                try callback.send(callback.ctx, id, token, rejected);
                return;
            },
            else => return err,
        };
        errdefer msg.deinit(self.allocator);
        const name = d.get("data").?.object.get("name").?.string;
        const receipt_text = try std.fmt.allocPrint(self.allocator, "Received /{s}. Command output appears in this channel.", .{name});
        defer self.allocator.free(receipt_text);
        const receipt = try nativeReceipt(self.allocator, receipt_text);
        defer self.allocator.free(receipt);
        try callback.send(callback.ctx, id, token, receipt);
        try b.publishInboundTimeout(msg, 0);
    }

    fn nativeCallbackConfig(allocator: std.mem.Allocator, id: []const u8, token: []const u8, body: []const u8) ![]u8 {
        if (!nativeUrlPart(id) or !nativeUrlPart(token) or body.len > 1024) return error.InvalidInteraction;
        const encoded_id = try encodeNativeSegment(allocator, id);
        defer allocator.free(encoded_id);
        const encoded_token = try encodeNativeSegment(allocator, token);
        defer allocator.free(encoded_token);
        return std.fmt.allocPrint(allocator, "url = \"https://discord.com/api/v10/interactions/{s}/{s}/callback\"\nrequest = \"POST\"\nheader = \"Content-Type: application/json\"\ndata-binary = {f}\nmax-time = 2\nconnect-timeout = 2\nsilent\noutput = \"{s}\"\nwrite-out = \"%{{http_code}}\"\n", .{ encoded_id, encoded_token, std.json.fmt(body, .{}), if (builtin.os.tag == .windows) "NUL" else "/dev/null" });
    }

    fn sendNativeCallback(ctx: *anyopaque, id: []const u8, token: []const u8, body: []const u8) !void {
        // Tests must inject a callback, including failures, instead of touching the network.
        if (builtin.is_test) return error.TestNetworkDisabled;
        const self: *DiscordChannel = @ptrCast(@alignCast(ctx));
        const config = try nativeCallbackConfig(self.allocator, id, token, body);
        defer self.allocator.free(config);
        // -q suppresses user curl config. Credentials travel only through stdin.
        var child = std_compat.process.Child.init(&.{ "curl", "-q", "--config", "-" }, self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        try child.spawn();
        var child_running = true;
        errdefer if (child_running) {
            if (child.stdin) |file| {
                file.close();
                child.stdin = null;
            }
            _ = child.kill() catch {};
            _ = child.wait() catch {};
        };
        try child.stdin.?.writeAll(config);
        child.stdin.?.close();
        child.stdin = null;
        const status = try child.stdout.?.readToEndAlloc(self.allocator, 16);
        defer self.allocator.free(status);
        const term = try child.wait();
        child_running = false;
        switch (term) {
            .exited => |code| if (code != 0) return error.InteractionCallbackFailed,
            else => return error.InteractionCallbackFailed,
        }
        try checkNativeCallbackStatus(status);
    }

    fn checkNativeCallbackStatus(status: []const u8) !void {
        if (status.len != 3 or status[0] != '2' or !std.ascii.isDigit(status[1]) or !std.ascii.isDigit(status[2])) return error.InteractionCallbackFailed;
    }

    fn handleInteractionCreate(self: *DiscordChannel, root_val: std.json.Value) !void {
        return self.handleInteractionCreateWithCallback(root_val, .{ .ctx = self, .send = sendNativeCallback });
    }

    fn handleInteractionCreateWithCallback(self: *DiscordChannel, root_val: std.json.Value, callback: NativeCallback) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse return;
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => return,
        };

        const interaction_type = d_obj.get("type") orelse return;
        if (interaction_type != .integer) return;
        switch (interaction_type.integer) {
            2 => return self.handleApplicationCommand(d_val, callback),
            3 => {},
            else => return,
        }

        const interaction_id = if (d_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const interaction_token = if (d_obj.get("token")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const channel_id = if (d_obj.get("channel_id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const interaction_message_id: ?[]const u8 = if (d_obj.get("message")) |v| switch (v) {
            .object => |msg_obj| if (msg_obj.get("id")) |id_val| switch (id_val) {
                .string => |s| s,
                else => null,
            } else null,
            else => null,
        } else null;
        const guild_id: ?[]const u8 = if (d_obj.get("guild_id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        const data_val = d_obj.get("data") orelse {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported interaction");
            return;
        };
        const data_obj = switch (data_val) {
            .object => |o| o,
            else => {
                self.answerInteraction(interaction_id, interaction_token, "Unsupported interaction");
                return;
            },
        };
        const custom_id = if (data_obj.get("custom_id")) |v| switch (v) {
            .string => |s| s,
            else => {
                self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
                return;
            },
        } else {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
            return;
        };
        const parsed_cb = interaction_choices.parseChoiceCallbackData(custom_id) orelse {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
            return;
        };

        const member_user_obj = if (d_obj.get("member")) |member_val| switch (member_val) {
            .object => |member_obj| if (member_obj.get("user")) |uval| switch (uval) {
                .object => |uobj| uobj,
                else => null,
            } else null,
            else => null,
        } else null;
        const direct_user_obj = if (d_obj.get("user")) |user_val| switch (user_val) {
            .object => |uobj| uobj,
            else => null,
        } else null;
        const user_obj = member_user_obj orelse direct_user_obj orelse {
            self.answerInteraction(interaction_id, interaction_token, "Missing user context");
            return;
        };

        const user_id = if (user_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const username: ?[]const u8 = if (user_obj.get("username")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
        const display_name: ?[]const u8 = if (user_obj.get("global_name")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        if (!root.isAllowedScoped("discord channel", self.allow_from, user_id)) {
            self.answerInteraction(interaction_id, interaction_token, "You are not allowed to use this button");
            return;
        }

        const selection = try self.consumeCallbackSelection(self.allocator, parsed_cb.token, parsed_cb.option_id, channel_id);
        switch (selection) {
            .ok => |submit_text| {
                defer self.allocator.free(submit_text);
                self.answerInteraction(interaction_id, interaction_token, null);

                const session_key = if (guild_id == null)
                    try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, user_id })
                else
                    try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
                defer self.allocator.free(session_key);

                var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
                defer metadata_buf.deinit(self.allocator);
                var metadata_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &metadata_buf);
                const mw = &metadata_writer.writer;
                try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
                try mw.writeAll(",\"account_id\":");
                try root.appendJsonStringW(mw, self.account_id);
                try mw.writeAll(",\"interaction\":\"button\"");
                if (std.mem.startsWith(u8, submit_text, "/model ")) {
                    try mw.writeAll(",\"replace_message\":true");
                }
                if (interaction_message_id) |message_id| {
                    try mw.writeAll(",\"message_id\":");
                    try root.appendJsonStringW(mw, message_id);
                }
                if (guild_id) |gid| {
                    try mw.writeAll(",\"guild_id\":");
                    try root.appendJsonStringW(mw, gid);
                }
                if (username) |uname| {
                    try mw.writeAll(",\"sender_username\":");
                    try root.appendJsonStringW(mw, uname);
                }
                if (display_name) |dname| {
                    try mw.writeAll(",\"sender_display_name\":");
                    try root.appendJsonStringW(mw, dname);
                }
                try mw.writeByte('}');
                metadata_buf = metadata_writer.toArrayList();

                var msg = try bus_mod.makeInboundFull(
                    self.allocator,
                    "discord",
                    user_id,
                    channel_id,
                    submit_text,
                    session_key,
                    &.{},
                    metadata_buf.items,
                );
                msg.trusted_sender = true;
                if (self.bus) |b| {
                    b.publishInbound(msg) catch |err| {
                        log.warn("Discord: failed to publish interaction message: {}", .{err});
                        msg.deinit(self.allocator);
                    };
                } else {
                    msg.deinit(self.allocator);
                }
            },
            .not_found, .expired => self.answerInteraction(interaction_id, interaction_token, "This menu has expired"),
            .invalid_chat => self.answerInteraction(interaction_id, interaction_token, "This button belongs to another chat"),
            .invalid_option => self.answerInteraction(interaction_id, interaction_token, "Unknown button selection"),
        }
    }

    /// Send IDENTIFY payload.
    fn sendIdentifyPayload(self: *DiscordChannel, ws: *websocket.WsClient) !void {
        var buf: [1024]u8 = undefined;
        const json = try buildIdentifyJson(&buf, self.token, self.intents);
        try ws.writeText(json);
    }

    /// Send RESUME payload.
    fn sendResumePayload(self: *DiscordChannel, ws: *websocket.WsClient) !void {
        const sid = self.session_id orelse return error.NoSessionId;
        const seq = self.sequence.load(.acquire);
        var buf: [512]u8 = undefined;
        const json = try buildResumeJson(&buf, self.token, sid, seq);
        try ws.writeText(json);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord send url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/messages", url);
}

test "discord typing url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.typingUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/typing", url);
}

test "discord sendTypingIndicator is no-op in tests" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    ch.sendTypingIndicator("123456");
}

test "discord typing handles start empty" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    try std.testing.expect(ch.typing_handles.get("123456") == null);
}

test "discord startTyping stores handle and stopTyping clears it" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    ch.running.store(true, .release);
    defer ch.stopAllTyping();

    try ch.startTyping("123456");
    try std.testing.expect(ch.typing_handles.get("123456") != null);
    std_compat.thread.sleep(50 * std.time.ns_per_ms);
    try ch.stopTyping("123456");
    try std.testing.expect(ch.typing_handles.get("123456") == null);
}

test "discord stopTyping is idempotent" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    try ch.stopTyping("123456");
    try ch.stopTyping("123456");
}

test "discord extract bot user id" {
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.Ghijk.abcdef");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id no dot" {
    try std.testing.expect(DiscordChannel.extractBotUserId("notokenformat") == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Discord Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "discord send url with different channel ids" {
    var buf: [256]u8 = undefined;
    const url1 = try DiscordChannel.sendUrl(&buf, "999");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/999/messages", url1);

    var buf2: [256]u8 = undefined;
    const url2 = try DiscordChannel.sendUrl(&buf2, "1234567890");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/1234567890/messages", url2);
}

test "discord extract bot user id multiple dots" {
    // Token format: base64(user_id).timestamp.hmac
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.fake.hmac");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id empty token" {
    // Empty string before dot means empty result
    const id = DiscordChannel.extractBotUserId("");
    try std.testing.expect(id == null);
}

test "discord extract bot user id single dot" {
    const id = DiscordChannel.extractBotUserId("abc.");
    try std.testing.expectEqualStrings("abc", id.?);
}

test "discord max message len constant" {
    try std.testing.expectEqual(@as(usize, 2000), DiscordChannel.MAX_MESSAGE_LEN);
}

test "discord gateway url constant" {
    try std.testing.expectEqualStrings("wss://gateway.discord.gg/?v=10&encoding=json", DiscordChannel.GATEWAY_URL);
}

test "discord init stores fields" {
    const ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", "guild-123", true);
    try std.testing.expectEqualStrings("my-bot-token", ch.token);
    try std.testing.expectEqualStrings("guild-123", ch.guild_id.?);
    try std.testing.expect(ch.allow_bots);
}

test "discord init no guild id" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expect(ch.guild_id == null);
    try std.testing.expect(!ch.allow_bots);
}

test "discord send url buffer too small returns error" {
    var buf: [10]u8 = undefined;
    const result = DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expect(if (result) |_| false else |_| true);
}

// ════════════════════════════════════════════════════════════════════════════
// New Gateway Helper Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord buildIdentifyJson" {
    var buf: [512]u8 = undefined;
    const json = try DiscordChannel.buildIdentifyJson(&buf, "mytoken", 37377);
    // Should contain op:2 and the token and intents
    try std.testing.expect(std.mem.indexOf(u8, json, "\"op\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "mytoken") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "37377") != null);
}

test "discord buildHeartbeatJson no sequence" {
    var buf: [64]u8 = undefined;
    const json = try DiscordChannel.buildHeartbeatJson(&buf, 0);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":null}", json);
}

test "discord buildHeartbeatJson with sequence" {
    var buf: [64]u8 = undefined;
    const json = try DiscordChannel.buildHeartbeatJson(&buf, 42);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":42}", json);
}

test "discord buildResumeJson" {
    var buf: [256]u8 = undefined;
    const json = try DiscordChannel.buildResumeJson(&buf, "mytoken", "session123", 99);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"op\":6") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "session123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "99") != null);
}

test "discord parseGatewayHost from wss url" {
    const host = DiscordChannel.parseGatewayHost("wss://us-east1.gateway.discord.gg");
    try std.testing.expectEqualStrings("us-east1.gateway.discord.gg", host);
}

test "discord parseGatewayHost with path" {
    const host = DiscordChannel.parseGatewayHost("wss://gateway.discord.gg/?v=10&encoding=json");
    try std.testing.expectEqualStrings("gateway.discord.gg", host);
}

test "discord parseGatewayHost no scheme returns original" {
    const host = DiscordChannel.parseGatewayHost("gateway.discord.gg");
    try std.testing.expectEqualStrings("gateway.discord.gg", host);
}

test "discord isMentioned with user id" {
    try std.testing.expect(DiscordChannel.isMentioned("<@123456> hello", "123456"));
    try std.testing.expect(DiscordChannel.isMentioned("hello <@!123456>", "123456"));
    try std.testing.expect(!DiscordChannel.isMentioned("hello world", "123456"));
    try std.testing.expect(!DiscordChannel.isMentioned("<@999999> hello", "123456"));
}

test "discord intents default" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expectEqual(@as(u32, 37377), ch.intents);
}

test "discord initFromConfig passes all fields" {
    const config_types = @import("../config_types.zig");
    const cfg = config_types.DiscordConfig{
        .account_id = "discord-main",
        .token = "my-token",
        .guild_id = "guild-1",
        .allow_bots = true,
        .allow_from = &.{ "user1", "user2" },
        .require_mention = true,
        .intents = 512,
    };
    const ch = DiscordChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("my-token", ch.token);
    try std.testing.expectEqualStrings("guild-1", ch.guild_id.?);
    try std.testing.expect(ch.allow_bots);
    try std.testing.expectEqualStrings("discord-main", ch.account_id);
    try std.testing.expectEqual(@as(usize, 2), ch.allow_from.len);
    try std.testing.expect(ch.require_mention);
    try std.testing.expectEqual(@as(u32, 512), ch.intents);
}

test "discord buildComponentsJson packs sixth option into final row" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "m1", .label = "One", .submit_text = "/model one" },
        .{ .id = "m2", .label = "Two", .submit_text = "/model two" },
        .{ .id = "m3", .label = "Three", .submit_text = "/model three" },
        .{ .id = "m4", .label = "Four", .submit_text = "/model four" },
        .{ .id = "prev", .label = "Prev", .submit_text = "/model page 1" },
        .{ .id = "next", .label = "Next", .submit_text = "/model page 3" },
    };
    var directive = try ch.buildChoicesDirectiveFromPayload(&choices);
    defer directive.deinit(alloc);

    const json = try ch.buildComponentsJson(directive, "abc");
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:m1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:prev\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:next\"") != null);
}

test "discord handleMessageCreate publishes inbound guild message with metadata" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"u-1"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","username":"discord-user","global_name":"Discord User","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord", msg.channel);
    try std.testing.expectEqualStrings("u-1", msg.sender_id);
    // Regression: only platform-authenticated events may carry operator provenance.
    try std.testing.expect(msg.trusted_sender);
    try std.testing.expectEqualStrings("c-1", msg.chat_id);
    try std.testing.expectEqualStrings("hello", msg.content);
    try std.testing.expectEqualStrings("discord:dc-main:channel:c-1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expect(meta.value.object.get("account_id") != null);
    try std.testing.expect(meta.value.object.get("is_dm") != null);
    try std.testing.expect(meta.value.object.get("guild_id") != null);
    try std.testing.expect(meta.value.object.get("sender_username") != null);
    try std.testing.expect(meta.value.object.get("sender_display_name") != null);
    try std.testing.expectEqualStrings("dc-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(!meta.value.object.get("is_dm").?.bool);
    try std.testing.expectEqualStrings("g-1", meta.value.object.get("guild_id").?.string);
    try std.testing.expectEqualStrings("discord-user", meta.value.object.get("sender_username").?.string);
    try std.testing.expectEqualStrings("Discord User", meta.value.object.get("sender_display_name").?.string);
}

test "discord handleMessageCreate empty allow_from denies inbound message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate wildcard allow_from permits inbound message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"*"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 1), event_bus.inboundDepth());
    var msg = event_bus.consumeInbound().?;
    defer msg.deinit(alloc);
}

test "discord handleInteractionCreate publishes synthetic inbound command" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"u-9"},
    });
    ch.setBus(&event_bus);
    defer ch.deinitPendingInteractions();

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "m1", .label = "Alpha", .submit_text = "/model alpha" },
        .{ .id = "next", .label = "Next", .submit_text = "/model page 2" },
    };
    var directive = try ch.buildChoicesDirectiveFromPayload(&choices);
    defer directive.deinit(alloc);
    try ch.registerPendingInteraction("tok1", "c-9", directive);

    const interaction_json =
        \\{"d":{"type":3,"id":"i-1","token":"itok","message":{"id":"message-1"},"channel_id":"c-9","guild_id":"g-9","member":{"user":{"id":"u-9","username":"discord-user","global_name":"Discord User"}},"data":{"custom_id":"nc1:tok1:m1"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, interaction_json, .{});
    defer parsed.deinit();

    try ch.handleInteractionCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord", msg.channel);
    try std.testing.expectEqualStrings("u-9", msg.sender_id);
    try std.testing.expectEqualStrings("c-9", msg.chat_id);
    try std.testing.expectEqualStrings("/model alpha", msg.content);
    try std.testing.expectEqualStrings("discord:dc-main:channel:c-9", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"interaction\":\"button\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"replace_message\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"message_id\":\"message-1\"") != null);
    try ch.handleInteractionCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate sets is_dm metadata for direct messages" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"u-7"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"dm-7","content":"hi dm","author":{"id":"u-7","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord:dc-main:direct:u-7", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expect(meta.value.object.get("is_dm") != null);
    try std.testing.expect(meta.value.object.get("is_dm").?.bool);
    try std.testing.expect(meta.value.object.get("guild_id") == null);
}

test "discord handleMessageCreate require_mention blocks unmentioned guild messages" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
        .allow_from = &.{"u-2"},
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","content":"plain text","author":{"id":"u-2","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate require_mention accepts reply to bot message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
        .allow_from = &.{"u-2"},
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":19,"content":"reply text","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"bot-1","bot":true}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 1), event_bus.inboundDepth());

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
}

test "discord handleMessageCreate require_mention still blocks reply to non-bot message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":19,"content":"reply text","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"other-user","bot":false}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate require_mention ignores non-reply references to bot message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":21,"content":"","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"bot-1","bot":true}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord dispatch sequence accepts lower values after session reset" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    defer {
        if (ch.session_id) |s| std.testing.allocator.free(s);
        if (ch.resume_gateway_url) |u| std.testing.allocator.free(u);
        if (ch.bot_user_id) |u| std.testing.allocator.free(u);
    }

    // Simulate stale sequence from an old session.
    ch.sequence.store(42, .release);

    var ws_dummy: websocket.WsClient = undefined;
    const ready_dispatch =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess-1","resume_gateway_url":"wss://gateway.discord.gg/?v=10&encoding=json","user":{"id":"bot-1"}}}
    ;
    try ch.handleGatewayMessage(&ws_dummy, ready_dispatch);

    try std.testing.expectEqual(@as(i64, 1), ch.sequence.load(.acquire));
}

test "discord invalid session non-resumable clears state and identifies" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "sess-1");
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(77, .release);

    const action = ch.resolveInvalidSessionAction(false);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.identify, action);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "discord invalid session resumable keeps state and resumes" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "sess-2");
    defer {
        if (ch.session_id) |s| alloc.free(s);
    }
    ch.sequence.store(123, .release);

    const action = ch.resolveInvalidSessionAction(true);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.resume_session, action);
    try std.testing.expect(ch.session_id != null);
    try std.testing.expectEqual(@as(i64, 123), ch.sequence.load(.acquire));
}

test "discord invalid session resumable without session falls back to identify" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(33, .release);

    const action = ch.resolveInvalidSessionAction(true);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.identify, action);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "discord intent bitmask guilds" {
    // GUILDS = 1
    try std.testing.expectEqual(@as(u32, 1), 1);
    // GUILD_MESSAGES = 512
    try std.testing.expectEqual(@as(u32, 512), 512);
    // MESSAGE_CONTENT = 32768
    try std.testing.expectEqual(@as(u32, 32768), 32768);
    // DIRECT_MESSAGES = 4096
    try std.testing.expectEqual(@as(u32, 4096), 4096);
    // Default intents = 1|512|32768|4096 = 37377
    try std.testing.expectEqual(@as(u32, 37377), 1 | 512 | 32768 | 4096);
}

test "DiscordChannel create + healthCheck + stop leaks zero bytes" {
    // DiscordChannel holds no heap allocations at init-time.  No deinit needed.
    var ch_struct = DiscordChannel.initFromConfig(std.testing.allocator, .{
        .token = "test-bot-token",
    });

    const ch = ch_struct.channel();
    _ = ch.healthCheck();
    ch.stop();
}

test "discord health check tolerates expected heartbeat idle window" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    ch.running.store(true, .release);
    ch.heartbeat_interval_ms.store(40_000, .release);
    ch.last_gateway_activity_ms.store(1_000_000, .release);

    // Within 3× heartbeat window (120s) — must still be healthy.
    try std.testing.expect(ch.gatewayHealthyAt(1_119_999));
}

test "discord health check fails after stale gateway idle" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    ch.running.store(true, .release);
    ch.heartbeat_interval_ms.store(40_000, .release);
    // Regression: a node could stay Discord-online while the gateway socket stopped
    // delivering events — heartbeat ACKs ceased but the process didn't restart.
    ch.last_gateway_activity_ms.store(1_000_000, .release);

    // Past 3× heartbeat window (120s) — must be stale.
    try std.testing.expect(!ch.gatewayHealthyAt(1_120_001));
}

test "discord gateway restart refreshes stale activity baseline" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    ch.running.store(true, .release);
    ch.heartbeat_interval_ms.store(40_000, .release);
    ch.last_gateway_activity_ms.store(1_000_000, .release);
    try std.testing.expect(!ch.gatewayHealthyAt(1_120_001));

    // Regression: after the watchdog restarts the gateway, the next connection
    // attempt must not inherit the stale socket timestamp and immediately fail
    // health checks before DNS/TCP/TLS has its own grace window.
    ch.last_gateway_activity_ms.store(1_120_001, .release);
    try std.testing.expect(ch.gatewayHealthyAt(1_130_001));
    try std.testing.expect(!ch.gatewayHealthyAt(1_240_002));
}

test "discord handleReady resets consecutive_reconnects to zero" {
    // Regression: rapid op-7 reconnect storms; READY must reset the backoff counter.
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    defer {
        if (ch.session_id) |s| alloc.free(s);
        if (ch.resume_gateway_url) |u| alloc.free(u);
        if (ch.bot_user_id) |u| alloc.free(u);
    }
    ch.consecutive_reconnects = 3;

    const ready_json =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess-rc","resume_gateway_url":"wss://gateway.discord.gg/?v=10&encoding=json","user":{"id":"bot-rc"}}}
    ;
    var ws_dummy: websocket.WsClient = undefined;
    try ch.handleGatewayMessage(&ws_dummy, ready_json);

    try std.testing.expectEqual(@as(u32, 0), ch.consecutive_reconnects);
}

test "discord reconnect backoff clears session on exhaustion" {
    // Regression: after MAX_RECONNECT_ATTEMPTS consecutive op-7s the session must be
    // cleared so the next attempt does a fresh IDENTIFY rather than looping forever.
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "stale-sess");
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(99, .release);
    ch.consecutive_reconnects = DiscordChannel.MAX_RECONNECT_ATTEMPTS - 1;

    const reconnect = ch.recordReconnectRequest();

    try std.testing.expectEqual(DiscordChannel.MAX_RECONNECT_ATTEMPTS, reconnect.attempt);
    try std.testing.expectEqual(@as(u64, 16_000), reconnect.backoff_ms);
    try std.testing.expect(reconnect.cleared_session);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), ch.consecutive_reconnects);
}

const NativeCallbackCapture = struct {
    allocator: std.mem.Allocator,
    body: ?[]u8 = null,
    calls: usize = 0,
    fail: bool = false,
    status: []const u8 = "204",
    close_bus: ?*bus_mod.Bus = null,
    observe_bus: ?*bus_mod.Bus = null,

    fn callback(self: *NativeCallbackCapture) DiscordChannel.NativeCallback {
        return .{ .ctx = self, .send = send };
    }

    fn send(ctx: *anyopaque, _: []const u8, _: []const u8, body: []const u8) !void {
        const self: *NativeCallbackCapture = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (self.observe_bus) |b| try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
        if (self.body) |old| self.allocator.free(old);
        self.body = try self.allocator.dupe(u8, body);
        if (self.close_bus) |b| b.close();
        if (self.fail) return error.CallbackFailed;
        try DiscordChannel.checkNativeCallbackStatus(self.status);
    }

    fn deinit(self: *NativeCallbackCapture) void {
        if (self.body) |body| self.allocator.free(body);
    }
};

fn nativeTestEvent(allocator: std.mem.Allocator, name: []const u8, options: []const u8, context: []const u8) !std.json.Parsed(std.json.Value) {
    const json = try std.fmt.allocPrint(allocator, "{{\"d\":{{\"type\":2,\"id\":\"123\",\"token\":\"test-interaction-token\",\"channel_id\":\"thread-9\",{s},\"data\":{{\"type\":1,\"name\":{f}{s}}}}}}}", .{ context, std.json.fmt(name, .{}), options });
    defer allocator.free(json);
    return std.json.parseFromSlice(std.json.Value, allocator, json, .{});
}

const native_guild_context = "\"guild_id\":\"guild-9\",\"member\":{\"user\":{\"id\":\"user-9\",\"username\":\"neutral-user\",\"global_name\":\"Neutral User\"}}";
const native_dm_context = "\"user\":{\"id\":\"user-9\",\"username\":\"neutral-user\",\"global_name\":\"Neutral User\"}";

test "discord native catalog commands reach existing handlers with completed receipts" {
    // Regression: type 2 interactions must reach command dispatch rather than the button custom_id parser.
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-bot-token", .account_id = "secondary", .guild_id = "guild-9", .allow_from = &.{"user-9"}, .require_mention = true });
    ch.setBus(&b);
    var capture = NativeCallbackCapture{ .allocator = alloc, .observe_bus = &b };
    defer capture.deinit();
    const catalog = try DiscordChannel.loadCommandCatalog(alloc);
    defer catalog.deinit();
    try std.testing.expectEqual(@as(usize, 52), catalog.value.len);
    for (catalog.value) |command| {
        const event = try nativeTestEvent(alloc, command.name, "", native_guild_context);
        defer event.deinit();
        try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
        try std.testing.expectEqual(@as(usize, 1), b.inboundDepth());
        const msg = b.consumeInbound().?;
        defer msg.deinit(alloc);
        const expected = try std.fmt.allocPrint(alloc, "/{s}", .{command.name});
        defer alloc.free(expected);
        try std.testing.expectEqualStrings(expected, msg.content);
        const plan = @import("../agent/commands.zig").planTurnInput(msg.content);
        try std.testing.expect(plan.invoke_local_handler);
        try std.testing.expectEqualStrings("thread-9", msg.chat_id);
        try std.testing.expectEqualStrings("user-9", msg.sender_id);
        try std.testing.expectEqualStrings("discord:secondary:channel:thread-9", msg.session_key);
        const metadata = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
        defer metadata.deinit();
        try std.testing.expectEqualStrings("secondary", metadata.value.object.get("account_id").?.string);
        try std.testing.expectEqualStrings("application_command", metadata.value.object.get("interaction").?.string);
        try std.testing.expectEqualStrings("guild-9", metadata.value.object.get("guild_id").?.string);
        try std.testing.expectEqualStrings("neutral-user", metadata.value.object.get("sender_username").?.string);
        try std.testing.expectEqualStrings("Neutral User", metadata.value.object.get("sender_display_name").?.string);
        try std.testing.expect(!metadata.value.object.get("is_dm").?.bool);
        try std.testing.expect(!metadata.value.object.contains("message_id"));
        try std.testing.expect(!metadata.value.object.contains("replace_message"));
        try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "token") == null);
        const receipt = try std.json.parseFromSlice(std.json.Value, alloc, capture.body.?, .{});
        defer receipt.deinit();
        try std.testing.expectEqual(@as(i64, 4), receipt.value.object.get("type").?.integer);
        const receipt_data = receipt.value.object.get("data").?.object;
        try std.testing.expectEqual(@as(i64, 64), receipt_data.get("flags").?.integer);
        const expected_receipt = try std.fmt.allocPrint(alloc, "Received /{s}. Command output appears in this channel.", .{command.name});
        defer alloc.free(expected_receipt);
        try std.testing.expectEqualStrings(expected_receipt, receipt_data.get("content").?.string);
    }
    try std.testing.expectEqual(@as(usize, 52), capture.calls);
}

test "discord native args preserve escaped interior text and direct route" {
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-token", .account_id = "dm-account", .allow_from = &.{"user-9"}, .require_mention = true });
    ch.setBus(&b);
    var capture = NativeCallbackCapture{ .allocator = alloc };
    defer capture.deinit();
    const catalog = try DiscordChannel.loadCommandCatalog(alloc);
    defer catalog.deinit();
    for (catalog.value) |command| {
        if (command.options.len == 0) continue;
        const event = try nativeTestEvent(alloc, command.name, ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":\"  a \\\"quote\\\"\\nback\\\\slash  \"}]", native_dm_context);
        defer event.deinit();
        try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
        const msg = b.consumeInbound().?;
        defer msg.deinit(alloc);
        const expected = try std.fmt.allocPrint(alloc, "/{s} a \"quote\"\nback\\slash", .{command.name});
        defer alloc.free(expected);
        try std.testing.expectEqualStrings(expected, msg.content);
        try std.testing.expectEqualStrings("discord:dm-account:direct:user-9", msg.session_key);
        try std.testing.expectEqualStrings("thread-9", msg.chat_id);
        try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"is_dm\":true") != null);
    }
}

test "discord native rejects malformed options and no args commands" {
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-token", .allow_from = &.{"user-9"} });
    ch.setBus(&b);
    var capture = NativeCallbackCapture{ .allocator = alloc };
    defer capture.deinit();
    const invalid_options = [_][]const u8{
        ",\"options\":null",
        ",\"options\":{}",
        ",\"options\":[{}]",
        ",\"options\":[{\"type\":3,\"name\":\"other\",\"value\":\"x\"}]",
        ",\"options\":[{\"type\":4,\"name\":\"args\",\"value\":\"x\"}]",
        ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":1}]",
        ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":\"x\",\"options\":[]}]",
        ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":\"x\"},{\"type\":3,\"name\":\"args\",\"value\":\"y\"}]",
    };
    for (invalid_options) |options| {
        const event = try nativeTestEvent(alloc, "model", options, native_guild_context);
        defer event.deinit();
        try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
        try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    }
    const catalog = try DiscordChannel.loadCommandCatalog(alloc);
    defer catalog.deinit();
    for (catalog.value) |command| {
        if (command.options.len != 0) continue;
        const event = try nativeTestEvent(alloc, command.name, ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":\"x\"}]", native_guild_context);
        defer event.deinit();
        try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
        try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    }
    const unknown = try nativeTestEvent(alloc, "unknown-command", "", native_guild_context);
    defer unknown.deinit();
    try ch.handleInteractionCreateWithCallback(unknown.value, capture.callback());
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    try std.testing.expect(std.mem.indexOf(u8, capture.body.?, "unavailable") != null);
}

test "discord native identity and configured guild reject bypasses" {
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-token", .guild_id = "guild-9", .allow_from = &.{"user-9"}, .allow_bots = true });
    ch.setBus(&b);
    var capture = NativeCallbackCapture{ .allocator = alloc };
    defer capture.deinit();
    const contexts = [_][]const u8{
        native_dm_context,
        "\"guild_id\":\"other-guild\",\"member\":{\"user\":{\"id\":\"user-9\"}}",
        "\"guild_id\":\"guild-9\",\"user\":{\"id\":\"user-9\"}",
        "\"guild_id\":\"guild-9\",\"member\":null,\"user\":{\"id\":\"user-9\"}",
        "\"guild_id\":\"guild-9\",\"member\":{\"user\":{\"id\":\"other-user\"}},\"user\":{\"id\":\"user-9\"}",
        "\"guild_id\":\"guild-9\",\"member\":{\"user\":{\"id\":\"user-9\",\"bot\":true}}",
        "\"guild_id\":\"guild-9\",\"member\":{\"user\":{\"id\":\"user-9\",\"bot\":\"false\"}}",
        "\"guild_id\":null,\"user\":{\"id\":\"user-9\"}",
        "\"guild_id\":\"\",\"member\":{\"user\":{\"id\":\"user-9\"}}",
        "\"guild_id\":\"guild-9\",\"member\":{\"user\":{\"id\":\"\"}}",
    };
    for (contexts) |context| {
        const event = try nativeTestEvent(alloc, "status", "", context);
        defer event.deinit();
        try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
        try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    }
    ch.guild_id = null;
    const dm_with_member = try nativeTestEvent(alloc, "status", "", "\"member\":{\"user\":{\"id\":\"user-9\"}} ,\"user\":{\"id\":\"user-9\"}");
    defer dm_with_member.deinit();
    try ch.handleInteractionCreateWithCallback(dm_with_member.value, capture.callback());
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    ch.allow_from = &.{};
    const deny_default = try nativeTestEvent(alloc, "status", "", native_dm_context);
    defer deny_default.deinit();
    try ch.handleInteractionCreateWithCallback(deny_default.value, capture.callback());
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
}

test "discord native callback failure and shutdown never publish" {
    // Regression: acknowledging a command must not dispatch it if Discord rejects the receipt.
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-token", .allow_from = &.{"user-9"} });
    ch.setBus(&b);
    const event = try nativeTestEvent(alloc, "status", "", native_dm_context);
    defer event.deinit();
    var capture = NativeCallbackCapture{ .allocator = alloc, .fail = true };
    defer capture.deinit();
    try std.testing.expectError(error.CallbackFailed, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    capture.fail = false;
    for ([_][]const u8{ "400", "403", "429", "500", "000", "2000", "2xx" }) |status| {
        capture.status = status;
        try std.testing.expectError(error.InteractionCallbackFailed, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
        try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    }
    capture.status = "204";
    capture.close_bus = &b;
    try std.testing.expectError(error.Closed, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    const calls = capture.calls;
    try std.testing.expectError(error.Closed, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
    try std.testing.expectEqual(calls, capture.calls);
    ch.bus = null;
    try std.testing.expectError(error.NoBus, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
    try std.testing.expectEqual(calls, capture.calls);
}

test "discord native full queue frees prepared message" {
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    defer while (b.inboundDepth() > 0) b.consumeInbound().?.deinit(alloc);
    for (0..bus_mod.QUEUE_CAPACITY) |_| try b.publishInbound(try bus_mod.makeInbound(alloc, "discord", "user", "chat", "filler", "session"));
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-token", .allow_from = &.{"user-9"} });
    ch.setBus(&b);
    const event = try nativeTestEvent(alloc, "status", "", native_dm_context);
    defer event.deinit();
    var capture = NativeCallbackCapture{ .allocator = alloc };
    defer capture.deinit();
    try std.testing.expectError(error.Timeout, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
    try std.testing.expectEqual(bus_mod.QUEUE_CAPACITY, b.inboundDepth());
}

fn nativeAllocationFailure(allocator: std.mem.Allocator) !void {
    var b = bus_mod.Bus.init();
    defer b.close();
    defer while (b.inboundDepth() > 0) b.consumeInbound().?.deinit(allocator);
    var ch = DiscordChannel.initFromConfig(allocator, .{ .token = "test-token", .allow_from = &.{"user-9"} });
    ch.setBus(&b);
    const event = try nativeTestEvent(allocator, "model", ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":\"provider/model\"}]", native_dm_context);
    defer event.deinit();
    var capture = NativeCallbackCapture{ .allocator = allocator };
    defer capture.deinit();
    try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
}

test "discord native frees resources under allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nativeAllocationFailure, .{});
}

test "discord native rejects unsafe callback config and escapes receipt" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.InvalidInteraction, DiscordChannel.nativeCallbackConfig(alloc, "123", "", "{}"));
    const opaque_config = try DiscordChannel.nativeCallbackConfig(alloc, "123", "opaque+/=:\"\n\\token", "{}");
    defer alloc.free(opaque_config);
    try std.testing.expect(std.mem.indexOf(u8, opaque_config, "opaque%2B%2F%3D%3A%22%0A%5Ctoken/callback") != null);
    try std.testing.expect(std.mem.indexOf(u8, opaque_config, "\n\\token") == null);
    const receipt = try DiscordChannel.nativeReceipt(alloc, "a \"quote\"\nnext");
    defer alloc.free(receipt);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, receipt, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("a \"quote\"\nnext", parsed.value.object.get("data").?.object.get("content").?.string);
    const config = try DiscordChannel.nativeCallbackConfig(alloc, "123", "test-token", receipt);
    defer alloc.free(config);
    try std.testing.expect(std.mem.indexOf(u8, config, "max-time = 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "data-binary = \"{\\\"type\\\":4") != null);
}

test "discord native unsupported event types do not acknowledge or dispatch" {
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.init(alloc, "test-token", null, false);
    ch.setBus(&b);
    var capture = NativeCallbackCapture{ .allocator = alloc };
    defer capture.deinit();
    for ([_][]const u8{ "{\"d\":{}}", "{\"d\":{\"type\":1}}", "{\"d\":{\"type\":\"2\"}}", "{\"d\":{\"type\":4}}" }) |json| {
        const event = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
        defer event.deinit();
        try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
    }
    try std.testing.expectEqual(@as(usize, 0), capture.calls);
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
}

test "discord native validates required fields data kind and argument limit" {
    const alloc = std.testing.allocator;
    var b = bus_mod.Bus.init();
    defer b.close();
    var ch = DiscordChannel.initFromConfig(alloc, .{ .token = "test-token", .allow_from = &.{"user-9"} });
    ch.setBus(&b);
    var capture = NativeCallbackCapture{ .allocator = alloc };
    defer capture.deinit();
    for ([_][]const u8{ "id", "token", "channel_id" }) |field| {
        var event = try nativeTestEvent(alloc, "status", "", native_dm_context);
        defer event.deinit();
        const d = &event.value.object.getPtr("d").?.object;
        _ = d.swapRemove(field);
        if (std.mem.eql(u8, field, "channel_id")) {
            try ch.handleInteractionCreateWithCallback(event.value, capture.callback());
        } else {
            const calls = capture.calls;
            try std.testing.expectError(error.InvalidInteraction, ch.handleInteractionCreateWithCallback(event.value, capture.callback()));
            try std.testing.expectEqual(calls, capture.calls);
        }
        try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    }
    var wrong_kind = try nativeTestEvent(alloc, "status", "", native_dm_context);
    defer wrong_kind.deinit();
    wrong_kind.value.object.getPtr("d").?.object.getPtr("data").?.object.getPtr("type").?.* = .{ .integer = 2 };
    try ch.handleInteractionCreateWithCallback(wrong_kind.value, capture.callback());
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    const oversized_args = try alloc.alloc(u8, DiscordChannel.MAX_MESSAGE_LEN + 1);
    defer alloc.free(oversized_args);
    @memset(oversized_args, 'a');
    const options = try std.fmt.allocPrint(alloc, ",\"options\":[{{\"type\":3,\"name\":\"args\",\"value\":{f}}}]", .{std.json.fmt(oversized_args, .{})});
    defer alloc.free(options);
    const oversized = try nativeTestEvent(alloc, "model", options, native_dm_context);
    defer oversized.deinit();
    try ch.handleInteractionCreateWithCallback(oversized.value, capture.callback());
    try std.testing.expectEqual(@as(usize, 0), b.inboundDepth());
    for ([_][]const u8{ ",\"options\":[]", ",\"options\":[{\"type\":3,\"name\":\"args\",\"value\":\" \\n \\t\"}]" }) |empty_options| {
        const empty = try nativeTestEvent(alloc, "model", empty_options, native_dm_context);
        defer empty.deinit();
        try ch.handleInteractionCreateWithCallback(empty.value, capture.callback());
        const msg = b.consumeInbound().?;
        defer msg.deinit(alloc);
        try std.testing.expectEqualStrings("/model", msg.content);
    }
}
