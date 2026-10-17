const std = @import("std");
const commands = @import("commands.zig");
const memory_mod = @import("../memory/root.zig");
const Agent = @import("root.zig").Agent;

pub const TurnPersistenceState = struct {
    history: []const Agent.OwnedMessage,
    total_tokens: u64,
};

fn persistedAssistantReply(history: []const Agent.OwnedMessage, response: []const u8) []const u8 {
    if (history.len == 0) return response;
    const last = history[history.len - 1];
    if (last.role != .assistant) return response;
    return last.content;
}

pub fn persistTurn(
    store: memory_mod.SessionStore,
    state: TurnPersistenceState,
    session_key: []const u8,
    content: []const u8,
    response: []const u8,
) void {
    const turn_input = commands.planTurnInput(content);

    if (turn_input.clear_session) {
        store.clearMessages(session_key) catch {};
        store.clearAutoSaved(session_key) catch {};
    }

    if (commands.persistedRuntimeCommand(content)) |runtime_command| {
        store.saveMessage(session_key, memory_mod.RUNTIME_COMMAND_ROLE, runtime_command) catch {};
    }

    if (turn_input.llm_user_message) |persisted_user| {
        // Persist canonical conversation history.
        // Local-only slash commands are skipped, but any input that
        // reached the LLM must persist with the exact same routing
        // decision used by Agent.turn().
        // When the turn ends with an assistant history message, prefer
        // that canonical text over the rendered reply so restored
        // sessions do not replay /usage footers or reasoning blocks.
        // Some degraded turns return a fallback response without
        // appending a final assistant history entry; in that case we
        // must persist the actual response instead of stale tool-step
        // assistant text from earlier in the turn.
        const persisted_assistant = persistedAssistantReply(state.history, response);
        store.saveMessage(session_key, "user", persisted_user) catch {};
        store.saveMessage(session_key, "assistant", persisted_assistant) catch {};
        store.saveUsage(session_key, state.total_tokens) catch {};
    }
}

test "persistTurn stores user and assistant messages in session history" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer {
        for (history.items) |msg| msg.deinit(allocator);
        history.deinit(allocator);
    }

    try history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "pong"),
    });

    persistTurn(store, .{ .history = history.items, .total_tokens = 42 }, "test-cli-session", "ping", "pong");

    const sessions = try store.listSessions(allocator, 10, 0);
    defer memory_mod.freeSessionInfos(allocator, sessions);
    try std.testing.expectEqual(@as(usize, 1), sessions.len);
    try std.testing.expectEqualStrings("test-cli-session", sessions[0].session_id);
    try std.testing.expectEqual(@as(u64, 2), sessions[0].message_count);

    const detailed = try store.loadMessagesDetailed(allocator, "test-cli-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expectEqualStrings("user", detailed[0].role);
    try std.testing.expectEqualStrings("ping", detailed[0].content);
    try std.testing.expectEqualStrings("assistant", detailed[1].role);
    try std.testing.expectEqualStrings("pong", detailed[1].content);
    try std.testing.expectEqual(@as(?u64, 42), try store.loadUsage("test-cli-session"));
}

test "persistTurn clears prior session history on reset" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveMessage("test-cli-session", "user", "old");
    try store.saveMessage("test-cli-session", "assistant", "history");

    // Regression: local resets clear saved history without saving a synthetic greeting turn.
    persistTurn(store, .{ .history = &.{}, .total_tokens = 0 }, "test-cli-session", "/reset", "Session cleared.");

    const detailed = try store.loadMessagesDetailed(allocator, "test-cli-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 0), detailed.len);
}

test "persistTurn falls back to rendered response when assistant history is absent" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer history.deinit(allocator);

    // Regression: degraded turns can return a response without appending a final
    // assistant history message, so persistence must keep the rendered reply.
    persistTurn(store, .{ .history = history.items, .total_tokens = 9 }, "fallback-session", "hello", "fallback reply");

    const detailed = try store.loadMessagesDetailed(allocator, "fallback-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expectEqualStrings("assistant", detailed[1].role);
    try std.testing.expectEqualStrings("fallback reply", detailed[1].content);
}

test "persistTurn does not persist system prompt history entries" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer {
        for (history.items) |msg| msg.deinit(allocator);
        history.deinit(allocator);
    }

    try history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "ops contact admin@example.com token=sk-system-secret"),
    });
    try history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "ok"),
    });

    persistTurn(store, .{ .history = history.items, .total_tokens = 1 }, "system-history-session", "hello", "ok");

    const detailed = try store.loadMessagesDetailed(allocator, "system-history-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    for (detailed) |message| {
        try std.testing.expect(!std.mem.eql(u8, message.role, "system"));
        try std.testing.expect(std.mem.indexOf(u8, message.content, "admin@example.com") == null);
        try std.testing.expect(std.mem.indexOf(u8, message.content, "sk-system-secret") == null);
    }
}
