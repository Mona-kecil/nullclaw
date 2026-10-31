const std = @import("std");
const root = @import("root.zig");
const Config = @import("../config.zig").Config;
const http = @import("../http_util.zig");
const json = @import("../json_util.zig");

pub const Binding = struct { token: []const u8, guild_id: []const u8, operator_discord_id: []const u8 };

pub fn bindingFromConfig(cfg: *const Config) ?Binding {
    if (cfg.operator_identity.discord_id.len == 0) return null;
    if (!validId(cfg.operator_identity.discord_id)) {
        std.log.warn("discord_manage disabled: invalid operator id", .{});
        return null;
    }
    var binding: ?Binding = null;
    for (cfg.channels.discord) |account| {
        const guild = account.guild_id orelse continue;
        if (!validId(guild)) {
            std.log.warn("discord_manage disabled: invalid guild id", .{});
            return null;
        }
        if (binding != null) {
            std.log.warn("discord_manage disabled: multiple guild bindings", .{});
            return null;
        }
        binding = .{ .token = account.token, .guild_id = guild, .operator_discord_id = cfg.operator_identity.discord_id };
    }
    return binding;
}

const CreateChannel = struct { name: []const u8, channel_type: u8, topic: ?[]const u8, parent_id: ?[]const u8 };
const UpdateChannel = struct { id: []const u8, name: ?[]const u8, topic: ?[]const u8, parent_id: ?[]const u8 };
const Operation = union(enum) { list, create: CreateChannel, update: UpdateChannel, delete: []const u8 };
const ParseResult = union(enum) { operation: Operation, fail: []const u8 };

fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > 20) return false;
    for (id) |c| if (c < '0' or c > '9') return false;
    return true;
}

fn parse(args: root.JsonObjectMap) ParseResult {
    const action = root.getString(args, "action") orelse return .{ .fail = "Missing action" };
    if (std.mem.eql(u8, action, "list")) return .{ .operation = .list };
    if (!std.mem.eql(u8, action, "create") and !std.mem.eql(u8, action, "update") and !std.mem.eql(u8, action, "delete")) return .{ .fail = "Invalid action" };
    var id: []const u8 = "";
    if (!std.mem.eql(u8, action, "create")) {
        id = root.getString(args, "id") orelse return .{ .fail = "Invalid channel id" };
        if (!validId(id)) return .{ .fail = "Invalid channel id" };
        if (std.mem.eql(u8, action, "delete")) return .{ .operation = .{ .delete = id } };
    }
    var name: ?[]const u8 = null;
    if (args.contains("name")) {
        name = std.mem.trim(u8, root.getString(args, "name") orelse return .{ .fail = "Invalid name" }, " \t\r\n");
        const count = std.unicode.utf8CountCodepoints(name.?) catch return .{ .fail = "Invalid name" };
        if (count == 0 or count > 100) return .{ .fail = "Invalid name" };
    }
    var topic: ?[]const u8 = null;
    if (args.contains("topic")) {
        topic = root.getString(args, "topic") orelse return .{ .fail = "Invalid topic" };
        const count = std.unicode.utf8CountCodepoints(topic.?) catch return .{ .fail = "Invalid topic" };
        if (count > 1024) return .{ .fail = "Invalid topic" };
    }
    var parent: ?[]const u8 = null;
    if (args.contains("parent_id")) {
        parent = root.getString(args, "parent_id") orelse return .{ .fail = "Invalid parent id" };
        if (!validId(parent.?)) return .{ .fail = "Invalid parent id" };
    }
    if (std.mem.eql(u8, action, "update")) {
        if (name == null and topic == null and parent == null) return .{ .fail = "Update requires at least one field" };
        return .{ .operation = .{ .update = .{ .id = id, .name = name, .topic = topic, .parent_id = parent } } };
    }
    const channel_name = name orelse return .{ .fail = "Invalid name" };
    var channel_type: u8 = 0;
    if (args.contains("type")) {
        const t = root.getString(args, "type") orelse return .{ .fail = "Invalid channel type" };
        if (std.mem.eql(u8, t, "text")) {
            channel_type = 0;
        } else if (std.mem.eql(u8, t, "voice")) {
            channel_type = 2;
        } else if (std.mem.eql(u8, t, "category")) {
            channel_type = 4;
        } else return .{ .fail = "Invalid channel type" };
    }
    return .{ .operation = .{ .create = .{ .name = channel_name, .channel_type = channel_type, .topic = topic, .parent_id = parent } } };
}

fn realTransport(allocator: std.mem.Allocator, method: std.http.Method, url: []const u8, body: ?[]const u8, token: []const u8) !http.HttpResponse {
    const auth = try std.fmt.allocPrint(allocator, "Authorization: Bot {s}", .{token});
    defer allocator.free(auth);
    return http.httpRequestWithStatus(allocator, method, url, body, &.{auth}, if (body != null) "application/json" else null, null);
}

pub const DiscordManageTool = struct {
    binding: Binding,
    transport: *const fn (std.mem.Allocator, std.http.Method, []const u8, ?[]const u8, []const u8) anyerror!http.HttpResponse = realTransport,
    pub const tool_name = "discord_manage";
    pub const tool_description = "List, create, update, or delete channels in the configured Discord server.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["list","create","update","delete"]},"id":{"type":"string","description":"Channel ID, required for update and delete"},"name":{"type":"string","description":"Required for create"},"type":{"type":"string","enum":["text","voice","category"]},"topic":{"type":"string"},"parent_id":{"type":"string"}},"required":["action"]}
    ;
    const vtable = root.ToolVTable(@This());
    pub fn tool(self: *DiscordManageTool) root.Tool {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn request(self: *DiscordManageTool, a: std.mem.Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8) !http.HttpResponse {
        const url = try std.fmt.allocPrint(a, "https://discord.com/api/v10{s}", .{path});
        defer a.free(url);
        return self.transport(a, method, url, body, self.binding.token);
    }

    pub fn execute(self: *DiscordManageTool, a: std.mem.Allocator, args: root.JsonObjectMap) !root.ToolResult {
        const sender = root.threadTrustedSender() orelse return root.ToolResult.fail("Discord operator authorization required");
        if (!std.mem.eql(u8, sender.channel, "discord") or !std.mem.eql(u8, sender.sender_id, self.binding.operator_discord_id)) return root.ToolResult.fail("Discord operator authorization required");
        const op = switch (parse(args)) {
            .fail => |msg| return root.ToolResult.fail(msg),
            .operation => |operation| operation,
        };
        const id: ?[]const u8 = switch (op) {
            .update => |u| u.id,
            .delete => |d| d,
            else => null,
        };
        const path = if (id) |channel_id| try std.fmt.allocPrint(a, "/channels/{s}", .{channel_id}) else try std.fmt.allocPrint(a, "/guilds/{s}/channels", .{self.binding.guild_id});
        defer a.free(path);
        if (id != null) {
            const check = self.request(a, .GET, path, null) catch return root.ToolResult.fail("Discord request failed");
            defer a.free(check.body);
            if (check.status_code < 200 or check.status_code >= 300) return statusError(a, check);
            const parsed = std.json.parseFromSlice(std.json.Value, a, check.body, .{}) catch return root.ToolResult.fail("Invalid Discord response");
            defer parsed.deinit();
            const guild = if (parsed.value == .object) root.getString(parsed.value.object, "guild_id") else null;
            if (guild == null or !std.mem.eql(u8, guild.?, self.binding.guild_id)) return root.ToolResult.fail("Channel is outside the configured guild");
        }
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(a);
        const method: std.http.Method = switch (op) {
            .list => .GET,
            .delete => .DELETE,
            .create => |c| blk: {
                try body.append(a, '{');
                try json.appendJsonKeyValue(&body, a, "name", c.name);
                try body.appendSlice(a, ",\"type\":");
                try body.append(a, '0' + c.channel_type);
                try appendFields(&body, a, c.topic, c.parent_id);
                try body.append(a, '}');
                break :blk .POST;
            },
            .update => |u| blk: {
                try body.append(a, '{');
                var comma = false;
                if (u.name) |name| {
                    try json.appendJsonKeyValue(&body, a, "name", name);
                    comma = true;
                }
                if (u.topic) |topic| {
                    if (comma) try body.append(a, ',');
                    try json.appendJsonKeyValue(&body, a, "topic", topic);
                    comma = true;
                }
                if (u.parent_id) |parent| {
                    if (comma) try body.append(a, ',');
                    try json.appendJsonKeyValue(&body, a, "parent_id", parent);
                }
                try body.append(a, '}');
                break :blk .PATCH;
            },
        };
        const response = self.request(a, method, path, if (body.items.len == 0) null else body.items) catch return root.ToolResult.fail("Discord request failed");
        defer a.free(response.body);
        if (response.status_code < 200 or response.status_code >= 300) return statusError(a, response);
        if (op == .list) return projectList(a, response.body);
        if (op == .create or op == .update) {
            const parsed = std.json.parseFromSlice(std.json.Value, a, response.body, .{}) catch return root.ToolResult.ok("Discord channel operation succeeded");
            defer parsed.deinit();
            if (parsed.value != .object) return root.ToolResult.ok("Discord channel operation succeeded");
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(a);
            try projectChannel(&out, a, parsed.value);
            return .{ .success = true, .output = try out.toOwnedSlice(a) };
        }
        return root.ToolResult.ok("Discord channel operation succeeded");
    }
};

fn appendFields(body: *std.ArrayList(u8), a: std.mem.Allocator, topic: ?[]const u8, parent: ?[]const u8) !void {
    if (topic) |t| {
        try body.append(a, ',');
        try json.appendJsonKeyValue(body, a, "topic", t);
    }
    if (parent) |p| {
        try body.append(a, ',');
        try json.appendJsonKeyValue(body, a, "parent_id", p);
    }
}

fn statusError(a: std.mem.Allocator, response: http.HttpResponse) !root.ToolResult {
    var retry: ?f64 = null;
    if (response.status_code == 429) {
        if (std.json.parseFromSlice(std.json.Value, a, response.body, .{})) |parsed| {
            defer parsed.deinit();
            if (parsed.value == .object) if (parsed.value.object.get("retry_after")) |v| {
                retry = switch (v) {
                    .float => v.float,
                    .integer => @floatFromInt(v.integer),
                    else => null,
                };
            };
        } else |_| {}
    }
    const detail: []const u8 = switch (response.status_code) {
        401 => "authentication failed",
        403 => "bot needs Manage Channels permission",
        404 => "channel or guild not found",
        429 => "rate limited",
        else => "request failed",
    };
    const msg = if (retry) |r| try std.fmt.allocPrint(a, "Discord HTTP {d}: {s}; retry after {d} seconds", .{ response.status_code, detail, r }) else try std.fmt.allocPrint(a, "Discord HTTP {d}: {s}", .{ response.status_code, detail });
    return .{ .success = false, .output = "", .error_msg = msg };
}

fn projectList(a: std.mem.Allocator, raw: []const u8) !root.ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, a, raw, .{}) catch return root.ToolResult.fail("Invalid Discord response");
    defer parsed.deinit();
    if (parsed.value != .array) return root.ToolResult.fail("Invalid Discord response");
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.append(a, '[');
    for (parsed.value.array.items, 0..) |item, i| {
        if (item != .object) {
            out.deinit(a);
            return root.ToolResult.fail("Invalid Discord response");
        }
        if (i != 0) try out.append(a, ',');
        try projectChannel(&out, a, item);
    }
    try out.append(a, ']');
    return .{ .success = true, .output = try out.toOwnedSlice(a) };
}

fn projectChannel(out: *std.ArrayList(u8), a: std.mem.Allocator, item: std.json.Value) !void {
    try out.append(a, '{');
    var comma = false;
    for ([_][]const u8{ "id", "name", "type", "parent_id", "position" }) |key| {
        if (item.object.get(key)) |value| {
            if (comma) try out.append(a, ',');
            try json.appendJsonKey(out, a, key);
            const encoded = try std.json.Stringify.valueAlloc(a, value, .{});
            defer a.free(encoded);
            try out.appendSlice(a, encoded);
            comma = true;
        }
    }
    try out.append(a, '}');
}

const Fake = struct {
    var calls: usize = 0;
    var methods: [4]std.http.Method = undefined;
    var last_body: [2048]u8 = undefined;
    var body_len: usize = 0;
    var status: u16 = 200;
    var response: []const u8 = "[]";
    var lookup: []const u8 = "{\"guild_id\":\"123\"}";
    fn send(a: std.mem.Allocator, method: std.http.Method, _: []const u8, body: ?[]const u8, _: []const u8) !http.HttpResponse {
        methods[calls] = method;
        calls += 1;
        if (body) |b| {
            @memcpy(last_body[0..b.len], b);
            body_len = b.len;
        }
        const content = if (calls == 1 and method == .GET and lookup.len > 0) lookup else response;
        return .{ .status_code = status, .body = try a.dupe(u8, content) };
    }
    fn reset() void {
        calls = 0;
        body_len = 0;
        status = 200;
        response = "[]";
        lookup = "";
    }
};

fn executeTest(t: *DiscordManageTool, input: []const u8) !root.ToolResult {
    var args = try root.parseTestArgs(input);
    defer args.deinit();
    return t.execute(std.testing.allocator, args.value.object);
}

const test_binding: Binding = .{ .token = "test-secret-token", .guild_id = "123", .operator_discord_id = "456" };

test "discord manage denies unverified and other senders before transport" {
    // Regression: forged webhook identities and other channels cannot authorize Discord writes.
    var t = DiscordManageTool{ .binding = test_binding, .transport = Fake.send };
    const previous = root.setThreadTrustedSender(null);
    defer _ = root.setThreadTrustedSender(previous);
    Fake.reset();
    try std.testing.expect(!(try executeTest(&t, "{}")).success);
    _ = root.setThreadTrustedSender(.{ .channel = "discord", .sender_id = "999" });
    try std.testing.expect(!(try executeTest(&t, "{}")).success);
    _ = root.setThreadTrustedSender(.{ .channel = "telegram", .sender_id = "456" });
    try std.testing.expect(!(try executeTest(&t, "{}")).success);
    try std.testing.expectEqual(@as(usize, 0), Fake.calls);
}

test "discord manage list create and validation" {
    var t = DiscordManageTool{ .binding = test_binding, .transport = Fake.send };
    const previous = root.setThreadTrustedSender(.{ .channel = "discord", .sender_id = "456" });
    defer _ = root.setThreadTrustedSender(previous);
    Fake.reset();
    Fake.response = "[{\"id\":\"1\",\"name\":\"general\",\"type\":0,\"parent_id\":null,\"position\":1,\"secret\":\"test-secret-token\"}]";
    const list = try executeTest(&t, "{\"action\":\"list\"}");
    defer std.testing.allocator.free(list.output);
    try std.testing.expectEqualStrings("[{\"id\":\"1\",\"name\":\"general\",\"type\":0,\"parent_id\":null,\"position\":1}]", list.output);
    Fake.reset();
    Fake.response = "{\"id\":\"1\",\"name\":\"a\",\"type\":2,\"parent_id\":null,\"position\":4}";
    const create = try executeTest(&t, "{\"action\":\"create\",\"name\":\"  a\\\"b  \",\"topic\":\"line\\nnext\",\"type\":\"voice\"}");
    defer std.testing.allocator.free(create.output);
    try std.testing.expect(create.success);
    try std.testing.expectEqualStrings(Fake.response, create.output);
    try std.testing.expectEqualStrings("{\"name\":\"a\\\"b\",\"type\":2,\"topic\":\"line\\nnext\"}", Fake.last_body[0..Fake.body_len]);
    Fake.reset();
    Fake.lookup = "{\"guild_id\":\"123\"}";
    Fake.response = "{\"id\":\"1\",\"name\":\"updated\",\"type\":0,\"parent_id\":null}";
    const update = try executeTest(&t, "{\"action\":\"update\",\"id\":\"1\",\"name\":\"updated\"}");
    defer std.testing.allocator.free(update.output);
    try std.testing.expectEqualStrings(Fake.response, update.output);
    // Regression: malformed success bodies must not turn completed writes into failures.
    for ([_][]const u8{ "{\"action\":\"create\",\"name\":\"a\"}", "{\"action\":\"update\",\"id\":\"1\",\"name\":\"a\"}" }) |input| {
        Fake.reset();
        Fake.lookup = "{\"guild_id\":\"123\"}";
        Fake.response = "invalid";
        const result = try executeTest(&t, input);
        try std.testing.expect(result.success);
        try std.testing.expectEqualStrings("Discord channel operation succeeded", result.output);
    }
    Fake.reset();
    try std.testing.expect(!(try executeTest(&t, "{\"action\":\"update\",\"id\":\"1\"}")).success);
    try std.testing.expect(!(try executeTest(&t, "{\"action\":\"delete\",\"id\":\"1/2\"}")).success);
    try std.testing.expect(!(try executeTest(&t, "{\"action\":\"create\",\"name\":\"x\",\"parent_id\":\"../1\"}")).success);
    try std.testing.expectEqual(@as(usize, 0), Fake.calls);
}

test "discord manage checks guild before writes" {
    // Regression: cross-guild channels and DMs must never receive a write.
    var t = DiscordManageTool{ .binding = test_binding, .transport = Fake.send };
    const previous = root.setThreadTrustedSender(.{ .channel = "discord", .sender_id = "456" });
    defer _ = root.setThreadTrustedSender(previous);
    for ([_][]const u8{ "{\"action\":\"update\",\"id\":\"1\",\"name\":\"x\"}", "{\"action\":\"delete\",\"id\":\"1\"}" }) |input| {
        for ([_][]const u8{ "{\"guild_id\":\"999\"}", "{}" }) |lookup| {
            Fake.reset();
            Fake.lookup = lookup;
            try std.testing.expect(!(try executeTest(&t, input)).success);
            try std.testing.expectEqual(@as(usize, 1), Fake.calls);
            try std.testing.expectEqual(std.http.Method.GET, Fake.methods[0]);
        }
    }
    Fake.reset();
    Fake.lookup = "{\"guild_id\":\"123\"}";
    try std.testing.expect((try executeTest(&t, "{\"action\":\"delete\",\"id\":\"1\"}")).success);
    try std.testing.expectEqual(@as(usize, 2), Fake.calls);
    try std.testing.expectEqual(std.http.Method.DELETE, Fake.methods[1]);
}

test "discord manage status errors hide response and credentials" {
    var t = DiscordManageTool{ .binding = test_binding, .transport = Fake.send };
    const previous = root.setThreadTrustedSender(.{ .channel = "discord", .sender_id = "456" });
    defer _ = root.setThreadTrustedSender(previous);
    for ([_]u16{ 403, 404, 429 }) |status| {
        Fake.reset();
        Fake.status = status;
        Fake.response = "{\"retry_after\":2.5,\"secret\":\"test-secret-token\"}";
        const result = try executeTest(&t, "{\"action\":\"list\"}");
        defer std.testing.allocator.free(result.error_msg.?);
        try std.testing.expect(!result.success);
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "test-secret-token") == null);
        const expected: []const u8 = switch (status) {
            403 => "Manage Channels",
            404 => "404",
            else => "2.5",
        };
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, expected) != null);
    }
}

test "discord manage binding requires one guild and operator" {
    var cfg: Config = .{ .allocator = std.testing.allocator, .workspace_dir = ".", .config_path = "" };
    const accounts = [_]@import("../config_types.zig").DiscordConfig{ .{ .token = "test-key", .guild_id = "123" }, .{ .token = "test-key", .guild_id = "456" } };
    cfg.channels.discord = accounts[0..1];
    try std.testing.expect(bindingFromConfig(&cfg) == null);
    cfg.operator_identity.discord_id = "789";
    cfg.channels.discord = &.{};
    try std.testing.expect(bindingFromConfig(&cfg) == null);
    cfg.channels.discord = accounts[0..1];
    try std.testing.expectEqualStrings("123", bindingFromConfig(&cfg).?.guild_id);
    cfg.operator_identity.discord_id = "bad";
    try std.testing.expect(bindingFromConfig(&cfg) == null);
    cfg.operator_identity.discord_id = "789";
    const invalid = [_]@import("../config_types.zig").DiscordConfig{.{ .token = "test-key", .guild_id = "123/4" }};
    cfg.channels.discord = &invalid;
    try std.testing.expect(bindingFromConfig(&cfg) == null);
    cfg.channels.discord = &accounts;
    try std.testing.expect(bindingFromConfig(&cfg) == null);
}

test "discord manage validates Unicode character limits" {
    // Regression: multi-byte names are limited by characters, not bytes.
    var args = try root.parseTestArgs("{\"action\":\"create\",\"name\":\"" ++ "é" ** 51 ++ "\"}");
    defer args.deinit();
    try std.testing.expect(parse(args.value.object) == .operation);
    var too_long = try root.parseTestArgs("{\"action\":\"create\",\"name\":\"" ++ "é" ** 101 ++ "\"}");
    defer too_long.deinit();
    try std.testing.expect(parse(too_long.value.object) == .fail);
    var topic = try root.parseTestArgs("{\"action\":\"create\",\"name\":\"a\",\"topic\":\"" ++ "é" ** 1024 ++ "\"}");
    defer topic.deinit();
    try std.testing.expect(parse(topic.value.object) == .operation);
    var long_topic = try root.parseTestArgs("{\"action\":\"create\",\"name\":\"a\",\"topic\":\"" ++ "é" ** 1025 ++ "\"}");
    defer long_topic.deinit();
    try std.testing.expect(parse(long_topic.value.object) == .fail);
    args.value.object.getPtr("name").?.* = .{ .string = "\xff" };
    try std.testing.expect(parse(args.value.object) == .fail);
}
