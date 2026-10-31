//! Reusable privacy redaction primitive.
//!
//! Detects and replaces email, phone (international plus-prefixed plus common
//! US/RU local forms), card numbers (Luhn-checked), anchored ID/passport runs,
//! and known token/secret patterns with
//! deterministic numbered placeholders like `[EMAIL_1]`, `[CARD_2]`.
//!
//! Stateful: same value within or across `redact()` calls reuses the same id.
//! Identity maps (`email_map`, …) key plaintext fingerprints by HMAC-SHA256
//! and never store the original value, so the default mode is one-way. The maps
//! are bounded; once the cap is reached, new identities collapse to KIND_0.
//!
//! `Config.record_originals = true` opts the redactor into a parallel
//! `placeholder_to_original` reverse map that retains plaintext PII for the
//! lifetime of the Redactor. This unlocks `unredact()` for callers that need
//! to rehydrate placeholders back to originals for user-facing display.
//! Originals stay in process RAM within a bounded reverse map; on-disk surfaces
//! (memory backend, history persistence) are not affected.

const std = @import("std");
const std_compat = @import("compat");

pub const Config = struct {
    redact_email: bool = true,
    redact_phone: bool = true,
    redact_card: bool = true,
    redact_id: bool = true,
    redact_tokens: bool = true,
    /// If true, redact() also records original PII alongside the placeholder so
    /// later unredact() calls can rehydrate. Off by default — the one-way
    /// "HMAC-only" contract holds. Opt in when the same Redactor is used to
    /// rehydrate display text within the agent process. Originals then live in
    /// process RAM for the redactor's lifetime; on-disk state is untouched.
    record_originals: bool = false,
    /// Upper bound for plaintext originals retained for display rehydration.
    /// Once the cap is reached, new placeholders remain one-way.
    max_originals: u32 = 1024,
    /// Upper bound for HMAC identity fingerprints retained by this Redactor.
    /// Existing identities keep their stable ids. New identities beyond the cap
    /// redact to KIND_0 without adding map entries, preserving privacy while
    /// bounding memory in long-lived sessions.
    max_identity_entries: u32 = 1024,
};

pub const Redactor = struct {
    allocator: std.mem.Allocator,
    config: Config,
    email_map: std.StringHashMap(u32),
    phone_map: std.StringHashMap(u32),
    card_map: std.StringHashMap(u32),
    id_map: std.StringHashMap(u32),
    token_map: std.StringHashMap(u32),
    /// Reverse lookup populated only when `config.record_originals == true`.
    /// Maps full placeholder string ("[EMAIL_1]") → original PII slice owned
    /// by `allocator`. Drives unredact(). Threat model: same as Agent.history
    /// (plaintext already resident in process); on-disk surface untouched.
    placeholder_to_original: std.StringHashMap([]u8),
    fingerprint_key: [32]u8,
    email_count: u32,
    phone_count: u32,
    card_count: u32,
    id_count: u32,
    token_count: u32,

    pub fn init(allocator: std.mem.Allocator, config: Config) Redactor {
        var fingerprint_key: [32]u8 = undefined;
        std_compat.crypto.random.bytes(&fingerprint_key);
        return .{
            .allocator = allocator,
            .config = config,
            .email_map = std.StringHashMap(u32).init(allocator),
            .phone_map = std.StringHashMap(u32).init(allocator),
            .card_map = std.StringHashMap(u32).init(allocator),
            .id_map = std.StringHashMap(u32).init(allocator),
            .token_map = std.StringHashMap(u32).init(allocator),
            .placeholder_to_original = std.StringHashMap([]u8).init(allocator),
            .fingerprint_key = fingerprint_key,
            .email_count = 0,
            .phone_count = 0,
            .card_count = 0,
            .id_count = 0,
            .token_count = 0,
        };
    }

    pub fn deinit(self: *Redactor) void {
        freeKeys(&self.email_map, self.allocator);
        freeKeys(&self.phone_map, self.allocator);
        freeKeys(&self.card_map, self.allocator);
        freeKeys(&self.id_map, self.allocator);
        freeKeys(&self.token_map, self.allocator);
        self.email_map.deinit();
        self.phone_map.deinit();
        self.card_map.deinit();
        self.id_map.deinit();
        self.token_map.deinit();
        freeOriginalsMap(&self.placeholder_to_original, self.allocator);
        self.placeholder_to_original.deinit();
    }

    pub fn reset(self: *Redactor) void {
        clearMap(&self.email_map, self.allocator);
        clearMap(&self.phone_map, self.allocator);
        clearMap(&self.card_map, self.allocator);
        clearMap(&self.id_map, self.allocator);
        clearMap(&self.token_map, self.allocator);
        clearOriginalsMap(&self.placeholder_to_original, self.allocator);
        self.email_count = 0;
        self.phone_count = 0;
        self.card_count = 0;
        self.id_count = 0;
        self.token_count = 0;
        std_compat.crypto.random.bytes(&self.fingerprint_key);
    }

    /// Redact PII / sensitive data from `input`. Returns slice owned by `dest_allocator`;
    /// caller must free with the same allocator. Internal state (maps, counters) lives
    /// on `self.allocator`, so a single Redactor can serve many short-lived destination
    /// allocators (e.g. per-turn arenas) while preserving cross-call placeholder ids.
    pub fn redact(self: *Redactor, dest_allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (!self.hasMatch(input)) {
            return dest_allocator.dupe(u8, input);
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(dest_allocator);

        var i: usize = 0;
        while (i < input.len) {
            // Priority order: tokens > email > card > phone > id.
            if (self.config.redact_tokens) {
                if (matchKeyValueSecret(input, i)) |kv| {
                    try out.appendSlice(dest_allocator, input[i..kv.value_start]);
                    const original = input[kv.value_start..kv.value_end];
                    const id = try self.intern(&self.token_map, &self.token_count, original);
                    try writePlaceholder(&out, dest_allocator, "TOKEN", id);
                    try self.recordOriginal("TOKEN", id, original);
                    i = kv.value_end;
                    continue;
                }
                if (matchBearerToken(input, i)) |bt| {
                    try out.appendSlice(dest_allocator, input[i .. i + bt.prefix_len]);
                    const original = input[i + bt.prefix_len .. bt.end];
                    const id = try self.intern(&self.token_map, &self.token_count, original);
                    try writePlaceholder(&out, dest_allocator, "TOKEN", id);
                    try self.recordOriginal("TOKEN", id, original);
                    i = bt.end;
                    continue;
                }
                if (matchPrefixToken(input, i)) |pt| {
                    const original = input[i..pt.end];
                    const id = try self.intern(&self.token_map, &self.token_count, original);
                    try writePlaceholder(&out, dest_allocator, "TOKEN", id);
                    try self.recordOriginal("TOKEN", id, original);
                    i = pt.end;
                    continue;
                }
            }
            if (self.config.redact_email) {
                if (matchEmail(input, i)) |em| {
                    const original = input[em.start..em.end];
                    const id = try self.intern(&self.email_map, &self.email_count, original);
                    try writePlaceholder(&out, dest_allocator, "EMAIL", id);
                    try self.recordOriginal("EMAIL", id, original);
                    i = em.end;
                    continue;
                }
            }
            if (self.config.redact_card) {
                if (matchCard(input, i)) |cd| {
                    const original = input[cd.start..cd.end];
                    var normalized: [32]u8 = undefined;
                    const key = digitsOnly(original, &normalized);
                    const id = try self.intern(&self.card_map, &self.card_count, key);
                    try writePlaceholder(&out, dest_allocator, "CARD", id);
                    try self.recordOriginal("CARD", id, original);
                    i = cd.end;
                    continue;
                }
            }
            if (self.config.redact_phone) {
                if (matchPhone(input, i)) |ph| {
                    const original = input[ph.start..ph.end];
                    var normalized: [32]u8 = undefined;
                    const key = digitsOnly(original, &normalized);
                    const id = try self.intern(&self.phone_map, &self.phone_count, key);
                    try writePlaceholder(&out, dest_allocator, "PHONE", id);
                    try self.recordOriginal("PHONE", id, original);
                    i = ph.end;
                    continue;
                }
            }
            if (self.config.redact_id) {
                if (matchAnchoredId(input, i)) |idm| {
                    try out.appendSlice(dest_allocator, input[i..idm.value_start]);
                    const original = input[idm.value_start..idm.value_end];
                    const id = try self.intern(&self.id_map, &self.id_count, original);
                    try writePlaceholder(&out, dest_allocator, "ID", id);
                    try self.recordOriginal("ID", id, original);
                    i = idm.value_end;
                    continue;
                }
            }

            try out.append(dest_allocator, input[i]);
            i += 1;
        }

        return try out.toOwnedSlice(dest_allocator);
    }

    pub fn wouldRedact(self: *Redactor, input: []const u8) bool {
        return self.hasMatch(input);
    }

    fn hasMatch(self: *Redactor, input: []const u8) bool {
        var i: usize = 0;
        while (i < input.len) : (i += 1) {
            if (self.config.redact_tokens) {
                if (matchKeyValueSecret(input, i) != null) return true;
                if (matchBearerToken(input, i) != null) return true;
                if (matchPrefixToken(input, i) != null) return true;
            }
            if (self.config.redact_email and matchEmail(input, i) != null) return true;
            if (self.config.redact_card and matchCard(input, i) != null) return true;
            if (self.config.redact_phone and matchPhone(input, i) != null) return true;
            if (self.config.redact_id and matchAnchoredId(input, i) != null) return true;
        }
        return false;
    }

    fn intern(self: *Redactor, map: *std.StringHashMap(u32), counter: *u32, value: []const u8) !u32 {
        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var digest: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&digest, value, &self.fingerprint_key);
        const fingerprint = std.fmt.bytesToHex(digest, .lower);

        if (map.get(fingerprint[0..])) |existing| return existing;
        if (self.config.max_identity_entries == 0 or self.identityEntryCount() >= self.config.max_identity_entries) {
            return 0;
        }
        const key_dup = try self.allocator.dupe(u8, fingerprint[0..]);
        errdefer self.allocator.free(key_dup);
        const new_id = counter.* + 1;
        try map.put(key_dup, new_id);
        counter.* = new_id;
        return new_id;
    }

    fn identityEntryCount(self: *const Redactor) u32 {
        const total = self.email_map.count() +
            self.phone_map.count() +
            self.card_map.count() +
            self.id_map.count() +
            self.token_map.count();
        return @intCast(@min(total, std.math.maxInt(u32)));
    }

    /// Cache the original PII slice under "[KIND_<id>]" so unredact() can
    /// restore it. No-op when `config.record_originals` is false.
    ///
    /// Idempotency rests on intern()'s contract: the same fingerprint
    /// (HMAC-SHA256 of the value, full 32-byte digest hex) maps to the same
    /// id, so a get-hit on the reverse map means the original we'd dup is
    /// byte-identical to the cached one. If a future change ever truncates
    /// the fingerprint or swaps the hash, this assumption breaks and the
    /// first-seen value would silently shadow later values for the same id —
    /// keep recordOriginal in lockstep with intern().
    ///
    /// On OOM after the placeholder has been written into `out` by the
    /// caller, errdefers free both dups; the next redact() retry finds the
    /// id already interned (same fingerprint) and re-records the original.
    fn recordOriginal(self: *Redactor, kind: []const u8, id: u32, original: []const u8) !void {
        if (!self.config.record_originals) return;
        if (id == 0) return;

        var key_buf: [32]u8 = undefined;
        const key_slice = try std.fmt.bufPrint(&key_buf, "[{s}_{d}]", .{ kind, id });
        if (self.placeholder_to_original.get(key_slice)) |_| return;
        if (self.config.max_originals == 0 or self.placeholder_to_original.count() >= self.config.max_originals) return;

        const key_dup = try self.allocator.dupe(u8, key_slice);
        errdefer self.allocator.free(key_dup);
        const value_dup = try self.allocator.dupe(u8, original);
        errdefer self.allocator.free(value_dup);
        try self.placeholder_to_original.put(key_dup, value_dup);
    }

    /// Whether this Redactor currently has originals to substitute back into
    /// placeholders. Callers (for example CLI display) gate downstream behavior
    /// on this, so plain turns without captured PII can still stream normally.
    pub fn wouldRehydrate(self: *const Redactor) bool {
        return self.config.record_originals and self.placeholder_to_original.count() > 0;
    }

    /// Replace `[EMAIL_N]` / `[PHONE_N]` / `[CARD_N]` / `[ID_N]` / `[TOKEN_N]`
    /// occurrences in `input` with the originals captured during prior
    /// redact() calls. Unknown placeholders pass through verbatim. Returns a
    /// slice owned by `dest_allocator`. Safe when `record_originals` was off
    /// during redaction — every placeholder will be unknown and preserved.
    pub fn unredact(self: *Redactor, dest_allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (std.mem.indexOfScalar(u8, input, '[') == null) {
            return dest_allocator.dupe(u8, input);
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(dest_allocator);

        var i: usize = 0;
        while (i < input.len) {
            if (input[i] == '[') {
                if (matchPlaceholderEnd(input, i)) |end| {
                    const key = input[i..end];
                    if (self.placeholder_to_original.get(key)) |original| {
                        try out.appendSlice(dest_allocator, original);
                    } else {
                        try out.appendSlice(dest_allocator, key);
                    }
                    i = end;
                    continue;
                }
            }
            try out.append(dest_allocator, input[i]);
            i += 1;
        }

        return try out.toOwnedSlice(dest_allocator);
    }
};

fn freeKeys(map: *std.StringHashMap(u32), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
}

fn clearMap(map: *std.StringHashMap(u32), allocator: std.mem.Allocator) void {
    freeKeys(map, allocator);
    map.clearRetainingCapacity();
}

fn freeOriginalsMap(map: *std.StringHashMap([]u8), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
}

fn clearOriginalsMap(map: *std.StringHashMap([]u8), allocator: std.mem.Allocator) void {
    freeOriginalsMap(map, allocator);
    map.clearRetainingCapacity();
}

/// If `input[pos..]` starts with `[KIND_DIGITS]` where KIND ∈
/// {EMAIL, PHONE, CARD, ID, TOKEN}, return the exclusive end index.
/// Case-sensitive — the placeholders we generate are uppercase.
fn matchPlaceholderEnd(input: []const u8, pos: usize) ?usize {
    if (pos >= input.len or input[pos] != '[') return null;
    var i = pos + 1;

    const kinds = [_][]const u8{ "EMAIL", "PHONE", "CARD", "TOKEN", "ID" };
    var matched_len: usize = 0;
    for (kinds) |k| {
        if (i + k.len > input.len) continue;
        if (std.mem.eql(u8, input[i .. i + k.len], k)) {
            matched_len = k.len;
            break;
        }
    }
    if (matched_len == 0) return null;
    i += matched_len;

    if (i >= input.len or input[i] != '_') return null;
    i += 1;

    const digits_start = i;
    while (i < input.len and std.ascii.isDigit(input[i])) i += 1;
    if (i == digits_start) return null;

    if (i >= input.len or input[i] != ']') return null;
    return i + 1;
}

fn writePlaceholder(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, kind: []const u8, id: u32) !void {
    var buf: [32]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "[{s}_{d}]", .{ kind, id });
    try out.appendSlice(allocator, formatted);
}

fn digitsOnly(input: []const u8, buf: []u8) []const u8 {
    var count: usize = 0;
    for (input) |c| {
        if (std.ascii.isDigit(c)) {
            if (count >= buf.len) break;
            buf[count] = c;
            count += 1;
        }
    }
    return buf[0..count];
}

// ════════════════════════════════════════════════════════════════════════════
// Detectors
// ════════════════════════════════════════════════════════════════════════════

fn isSecretChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or
        c == '-' or c == '_' or c == '.' or c == ':' or
        c == '%' or c == '+' or c == '/' or c == '=';
}

fn tokenEnd(input: []const u8, from: usize) usize {
    var end = from;
    while (end < input.len and isSecretChar(input[end])) end += 1;
    return end;
}

fn eqlLowercase(input: []const u8, kw: []const u8) bool {
    if (input.len != kw.len) return false;
    for (input, kw) |a, b| {
        if (std.ascii.toLower(a) != b) return false;
    }
    return true;
}

const PrefixToken = struct { end: usize };

fn matchPrefixToken(input: []const u8, pos: usize) ?PrefixToken {
    const PrefixSpec = struct { prefix: []const u8, min_suffix: usize };
    const prefixes = [_]PrefixSpec{
        .{ .prefix = "sk-", .min_suffix = 8 },
        .{ .prefix = "xoxb-", .min_suffix = 8 },
        .{ .prefix = "xoxp-", .min_suffix = 8 },
        .{ .prefix = "ghp_", .min_suffix = 8 },
        .{ .prefix = "gho_", .min_suffix = 8 },
        .{ .prefix = "ghs_", .min_suffix = 8 },
        .{ .prefix = "ghu_", .min_suffix = 8 },
        .{ .prefix = "glpat-", .min_suffix = 8 },
        .{ .prefix = "AKIA", .min_suffix = 16 },
        .{ .prefix = "pypi-", .min_suffix = 16 },
        .{ .prefix = "npm_", .min_suffix = 8 },
        .{ .prefix = "shpat_", .min_suffix = 8 },
    };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_') return null;
    }
    for (prefixes) |spec| {
        const prefix = spec.prefix;
        if (pos + prefix.len > input.len) continue;
        if (!std.mem.eql(u8, input[pos .. pos + prefix.len], prefix)) continue;
        const content_start = pos + prefix.len;
        const end = tokenEnd(input, content_start);
        if (end - content_start >= spec.min_suffix) {
            return .{ .end = end };
        }
    }
    return null;
}

const KeyValueMatch = struct { value_start: usize, value_end: usize };

fn matchKeyValueSecret(input: []const u8, pos: usize) ?KeyValueMatch {
    const keywords = [_][]const u8{
        "api_key",          "api-key",        "apikey",
        "token",            "password",       "passwd",
        "secret",           "api_secret",     "access_key",
        "access_token",     "refresh_token",  "id_token",
        "sig",              "signature",      "x-amz-signature",
        "x-amz-credential", "awsaccesskeyid",
    };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_' or prev == '-') return null;
    }
    for (keywords) |kw| {
        if (pos + kw.len >= input.len) continue;
        if (!eqlLowercase(input[pos .. pos + kw.len], kw)) continue;
        var sep_end = pos + kw.len;
        if (sep_end < input.len and (input[sep_end] == '"' or input[sep_end] == '\'')) {
            sep_end += 1;
            while (sep_end < input.len and input[sep_end] == ' ') sep_end += 1;
        }
        if (sep_end < input.len and (input[sep_end] == '=' or input[sep_end] == ':')) {
            sep_end += 1;
            while (sep_end < input.len and input[sep_end] == ' ') sep_end += 1;
            var quote: u8 = 0;
            if (sep_end < input.len and (input[sep_end] == '"' or input[sep_end] == '\'')) {
                quote = input[sep_end];
                sep_end += 1;
            }
            const value_start = sep_end;
            var value_end = value_start;
            if (quote != 0) {
                while (value_end < input.len and input[value_end] != quote) value_end += 1;
            } else {
                value_end = tokenEnd(input, value_start);
            }
            if (value_end > value_start) {
                return .{ .value_start = value_start, .value_end = value_end };
            }
        }
    }
    return null;
}

const BearerMatch = struct { prefix_len: usize, end: usize };

fn matchBearerToken(input: []const u8, pos: usize) ?BearerMatch {
    const variants = [_][]const u8{ "Bearer ", "bearer ", "BEARER " };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_') return null;
    }
    for (variants) |prefix| {
        if (pos + prefix.len > input.len) continue;
        if (!std.mem.eql(u8, input[pos .. pos + prefix.len], prefix)) continue;
        const token_start = pos + prefix.len;
        const end = tokenEnd(input, token_start);
        if (end > token_start) {
            return .{ .prefix_len = prefix.len, .end = end };
        }
    }
    return null;
}

const EmailMatch = struct { start: usize, end: usize };

fn isEmailLocalChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '+' or c == '-';
}

fn isEmailDomainChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '-';
}

fn matchEmail(input: []const u8, pos: usize) ?EmailMatch {
    if (pos > 0 and isEmailLocalChar(input[pos - 1])) return null;
    var i = pos;
    while (i < input.len and isEmailLocalChar(input[i])) i += 1;
    if (i == pos) return null;
    if (i >= input.len or input[i] != '@') return null;
    i += 1;
    const domain_start = i;
    while (i < input.len and isEmailDomainChar(input[i])) i += 1;
    if (i == domain_start) return null;
    var domain_end = i;
    while (domain_end > domain_start and (input[domain_end - 1] == '.' or input[domain_end - 1] == '-')) {
        domain_end -= 1;
    }
    if (domain_end == domain_start) return null;
    const domain = input[domain_start..domain_end];
    const last_dot = std.mem.lastIndexOfScalar(u8, domain, '.') orelse return null;
    if (last_dot == 0) return null;
    const tld = domain[last_dot + 1 ..];
    if (tld.len < 2) return null;
    for (tld) |c| {
        if (!std.ascii.isAlphabetic(c)) return null;
    }
    return .{ .start = pos, .end = domain_end };
}

const CardMatch = struct { start: usize, end: usize };

fn matchCard(input: []const u8, pos: usize) ?CardMatch {
    if (pos >= input.len or !std.ascii.isDigit(input[pos])) return null;
    if (pos > 0 and std.ascii.isAlphanumeric(input[pos - 1])) return null;
    var digits: [19]u8 = undefined;
    var digit_count: usize = 0;
    var i = pos;
    var last_digit_end = pos;
    while (i < input.len and digit_count < 19) {
        const c = input[i];
        if (std.ascii.isDigit(c)) {
            digits[digit_count] = c;
            digit_count += 1;
            i += 1;
            last_digit_end = i;
        } else if ((c == '-' or c == ' ') and digit_count > 0) {
            var next = i + 1;
            while (next < input.len and (input[next] == '-' or input[next] == ' ')) next += 1;
            if (next < input.len and std.ascii.isDigit(input[next])) {
                i = next;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    if (digit_count < 13 or digit_count > 19) return null;
    if (last_digit_end < input.len and std.ascii.isAlphanumeric(input[last_digit_end])) return null;
    if (!luhnValid(digits[0..digit_count])) return null;
    return .{ .start = pos, .end = last_digit_end };
}

fn luhnValid(digits: []const u8) bool {
    if (digits.len == 0) return false;
    var sum: u32 = 0;
    var alt = false;
    var idx: usize = digits.len;
    while (idx > 0) {
        idx -= 1;
        var d: u32 = digits[idx] - '0';
        if (alt) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        alt = !alt;
    }
    return sum % 10 == 0;
}

const PhoneMatch = struct { start: usize, end: usize };

fn matchPhone(input: []const u8, pos: usize) ?PhoneMatch {
    if (pos >= input.len) return null;
    if (input[pos] != '+' and input[pos] != '(' and !std.ascii.isDigit(input[pos])) return null;
    if (pos > 0 and std.ascii.isAlphanumeric(input[pos - 1])) return null;

    var digit_count: usize = 0;
    var separator_count: usize = 0;
    var last_digit_end = pos;
    const plus_prefixed = input[pos] == '+';
    var i = if (plus_prefixed) pos + 1 else pos;
    while (i < input.len and digit_count < 15) {
        const c = input[i];
        if (std.ascii.isDigit(c)) {
            digit_count += 1;
            i += 1;
            last_digit_end = i;
        } else if (c == '-' or c == ' ' or c == '(' or c == ')') {
            if (!plus_prefixed and digit_count == 0 and c != '(') return null;
            separator_count += 1;
            i += 1;
        } else {
            break;
        }
    }
    if (plus_prefixed) {
        if (digit_count < 7 or digit_count > 15) return null;
    } else {
        if (!(digit_count == 10 or digit_count == 11)) return null;
        if (separator_count < 2) return null;
        if (digit_count == 11) {
            const first_digit = firstDigit(input[pos..last_digit_end]) orelse return null;
            if (!(first_digit == '1' or first_digit == '7' or first_digit == '8')) return null;
        }
    }
    if (last_digit_end < input.len and std.ascii.isAlphanumeric(input[last_digit_end])) return null;
    if (isDateLike(input[pos..last_digit_end])) return null;
    return .{ .start = pos, .end = last_digit_end };
}

fn firstDigit(input: []const u8) ?u8 {
    for (input) |c| {
        if (std.ascii.isDigit(c)) return c;
    }
    return null;
}

fn isDateLike(raw: []const u8) bool {
    return hasYmdDatePrefix(raw) or hasDmyDatePrefix(raw);
}

fn hasYmdDatePrefix(raw: []const u8) bool {
    if (raw.len < 10) return false;
    if (raw[4] != '-' or raw[7] != '-') return false;
    if (!datePrefixTerminated(raw, 10)) return false;

    const year = parseFourDigits(raw[0..4]) orelse return false;
    const month = parseTwoDigits(raw[5], raw[6]) orelse return false;
    const day = parseTwoDigits(raw[8], raw[9]) orelse return false;
    return isPlausibleDate(year, month, day);
}

fn hasDmyDatePrefix(raw: []const u8) bool {
    if (raw.len < 10) return false;
    if (raw[2] != '-' or raw[5] != '-') return false;
    if (!datePrefixTerminated(raw, 10)) return false;

    const day = parseTwoDigits(raw[0], raw[1]) orelse return false;
    const month = parseTwoDigits(raw[3], raw[4]) orelse return false;
    const year = parseFourDigits(raw[6..10]) orelse return false;
    return isPlausibleDate(year, month, day);
}

fn datePrefixTerminated(raw: []const u8, prefix_len: usize) bool {
    return raw.len == prefix_len or raw[prefix_len] == ' ';
}

fn parseTwoDigits(a: u8, b: u8) ?u8 {
    if (!std.ascii.isDigit(a) or !std.ascii.isDigit(b)) return null;
    return (a - '0') * 10 + (b - '0');
}

fn parseFourDigits(raw: []const u8) ?u16 {
    if (raw.len != 4) return null;
    var value: u16 = 0;
    for (raw) |c| {
        if (!std.ascii.isDigit(c)) return null;
        const digit: u16 = @intCast(c - '0');
        value = value * 10 + digit;
    }
    return value;
}

fn isPlausibleDate(year: u16, month: u8, day: u8) bool {
    if (year < 1900 or year > 2199) return false;
    if (month < 1 or month > 12 or day < 1) return false;

    const max_day: u8 = switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => return false,
    };
    return day <= max_day;
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

const IdMatch = struct { value_start: usize, value_end: usize };

fn matchAnchoredId(input: []const u8, pos: usize) ?IdMatch {
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_' or prev == '-') return null;
    }

    const anchor_end = matchIdAnchor(input, pos) orelse return null;
    const value_start = skipIdSeparators(input, anchor_end);
    if (value_start >= input.len) return null;

    var value_end = value_start;
    var last_value_end = value_start;
    var alnum_count: usize = 0;
    var digit_count: usize = 0;
    while (value_end < input.len) {
        const c = input[value_end];
        if (std.ascii.isAlphanumeric(c)) {
            alnum_count += 1;
            if (std.ascii.isDigit(c)) digit_count += 1;
            value_end += 1;
            last_value_end = value_end;
        } else if ((c == ' ' or c == '-') and alnum_count > 0) {
            var next = value_end + 1;
            while (next < input.len and (input[next] == ' ' or input[next] == '-')) next += 1;
            if (next < input.len and std.ascii.isAlphanumeric(input[next])) {
                value_end = next;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if (alnum_count < 6 or alnum_count > 18) return null;
    if (digit_count < 4) return null;
    if (last_value_end < input.len) {
        const next = input[last_value_end];
        if (std.ascii.isAlphanumeric(next) or next == '_') return null;
    }
    return .{ .value_start = value_start, .value_end = last_value_end };
}

fn isIdSeparator(c: u8) bool {
    return c == ' ' or c == '\t' or c == ':' or c == '=' or c == '#' or c == '-' or c == '_';
}

fn skipIdSeparators(input: []const u8, from: usize) usize {
    var i = from;
    while (i < input.len) {
        if (isIdSeparator(input[i])) {
            i += 1;
            continue;
        }
        if (std.mem.startsWith(u8, input[i..], "№")) {
            i += "№".len;
            continue;
        }
        break;
    }
    return i;
}

fn matchIdAnchor(input: []const u8, pos: usize) ?usize {
    const ascii_anchors = [_][]const u8{
        "passport_number", "passport-number",
        "passport_no",     "passport-no",
        "passport number", "passport no",
        "passport",        "ssn",
        "snils",           "inn",
    };
    for (ascii_anchors) |anchor| {
        if (pos + anchor.len > input.len) continue;
        if (!eqlLowercase(input[pos .. pos + anchor.len], anchor)) continue;
        return pos + anchor.len;
    }
    if (pos + 2 <= input.len and eqlLowercase(input[pos .. pos + 2], "id")) {
        const end = pos + 2;
        if (end < input.len and (input[end] == ':' or input[end] == '=')) return end;
    }

    const unicode_anchors = [_][]const u8{
        "паспорт",
        "Паспорт",
        "ПАСПОРТ",
        "инн",
        "ИНН",
        "снилс",
        "СНИЛС",
    };
    for (unicode_anchors) |anchor| {
        if (pos + anchor.len > input.len) continue;
        if (!std.mem.eql(u8, input[pos .. pos + anchor.len], anchor)) continue;
        return pos + anchor.len;
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "Redactor redacts email to numbered placeholder" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "contact me at user@example.com");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("contact me at [EMAIL_1]", out);
}

test "Redactor email deterministic across calls" {
    // Regression: same email mentioned in different calls must reuse the same id.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const a = try r.redact(allocator, "a@b.co");
    defer allocator.free(a);
    const b = try r.redact(allocator, "a@b.co");
    defer allocator.free(b);
    try std.testing.expectEqualStrings("[EMAIL_1]", a);
    try std.testing.expectEqualStrings("[EMAIL_1]", b);
}

test "Redactor email before punctuation redacts only address" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "Mail me at user@example.com, or user@example.com.");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("Mail me at [EMAIL_1], or [EMAIL_1].", out);
}

test "Redactor preserves quoted secret delimiters" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "{\"api_key\":\"sk-live-secret\",\"token\": 'abc123'}");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("{\"api_key\":\"[TOKEN_1]\",\"token\": '[TOKEN_2]'}", out);
}

test "Redactor reset clears placeholder counters" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();

    const before = try r.redact(allocator, "a@b.co");
    defer allocator.free(before);
    try std.testing.expectEqualStrings("[EMAIL_1]", before);

    r.reset();

    const after = try r.redact(allocator, "x@y.zz");
    defer allocator.free(after);
    try std.testing.expectEqualStrings("[EMAIL_1]", after);
}

test "Redactor different emails get sequential ids" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "a@b.co and x@y.zz");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("[EMAIL_1] and [EMAIL_2]", out);
}

test "Redactor phone E.164 redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "call +12025551234 now");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("call [PHONE_1] now", out);
}

test "Redactor local US and RU phone formats redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "call (202) 555-1234, 202-555-1234, 8 999 123-45-67, +7 (999) 123-45-67");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("call [PHONE_1], [PHONE_1], [PHONE_2], [PHONE_3]", out);
}

test "Redactor phone without plus prefix is preserved" {
    // Regression: bare digit sequences without `+` must not match as phone numbers.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "see issue 12025551234");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("see issue 12025551234", out);
}

test "Redactor card with valid Luhn redacted" {
    // 4111 1111 1111 1111 is the standard Visa Luhn-valid test card.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "paid with 4111 1111 1111 1111");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("paid with [CARD_1]", out);
}

test "Redactor card with spaced hyphen separators redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "paid with 4111 - 1111 - 1111 - 1111");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("paid with [CARD_1]", out);
}

test "Redactor card without valid Luhn preserved" {
    // Regression: random 16-digit sequences must not match as cards.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "ref 1234567890123456");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("ref 1234567890123456", out);
}

test "Redactor passport anchored ID redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "passport: 4516378901");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("passport: [ID_1]", out);
}

test "Redactor anchored passport and national ID forms redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "passport no AB12345; паспорт № 4510 123456; SSN 123-45-6789; ИНН 1234567890; СНИЛС 123-456-789 00");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("passport no [ID_1]; паспорт № [ID_2]; SSN [ID_3]; ИНН [ID_4]; СНИЛС [ID_5]", out);
}

test "Redactor unanchored digit run preserved" {
    // Regression: digit runs without keyword anchor must not match as IDs.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "see ticket 4516378901 next week");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("see ticket 4516378901 next week", out);
}

test "Redactor technical id words without separator are preserved" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "issue id 123456 request id abc12345 trace id 123456");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("issue id 123456 request id abc12345 trace id 123456", out);
}

test "Redactor token prefix sk- redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "got sk-abcdef123");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("got [TOKEN_1]", out);
}

test "Redactor short prefix tokens are preserved" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "examples sk-a ghp_x AKIA123");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("examples sk-a ghp_x AKIA123", out);
}

test "Redactor key-value secret redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "api_key=mysecret");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("api_key=[TOKEN_1]", out);
}

test "Redactor URL-style secret params redact full value" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "token=abc/def+ghi%2B==&access_token=ya29.a0+bc/def%2Fghi&sig=deadbeef");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("token=[TOKEN_1]&access_token=[TOKEN_2]&sig=[TOKEN_3]", out);
}

test "Redactor signed URL param names are treated as secrets" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/aws4_request&AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("X-Amz-Signature=[TOKEN_1]&X-Amz-Credential=[TOKEN_2]&AWSAccessKeyId=[TOKEN_3]", out);
}

test "Redactor Bearer token redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "auth Bearer eyJhbGciOiJ");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("auth Bearer [TOKEN_1]", out);
}

test "Redactor preserves non-sensitive text verbatim" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "hello world, no secrets here");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("hello world, no secrets here", out);
}

test "Redactor idempotent on already-redacted text" {
    // Regression: re-running redact on its own output must produce identical text.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out1 = try r.redact(allocator, "user a@b.co exists");
    defer allocator.free(out1);
    const out2 = try r.redact(allocator, out1);
    defer allocator.free(out2);
    try std.testing.expectEqualStrings(out1, out2);
}

test "Redactor multi-category in single input" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "user a@b.co paid 4111 1111 1111 1111");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("user [EMAIL_1] paid [CARD_1]", out);
}

test "Redactor config disables category" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .redact_email = false });
    defer r.deinit();
    const out = try r.redact(allocator, "contact a@b.co");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("contact a@b.co", out);
}

test "Redactor empty input returns empty output" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "luhnValid accepts known valid card numbers" {
    try std.testing.expect(luhnValid("4111111111111111"));
    try std.testing.expect(luhnValid("5555555555554444"));
    try std.testing.expect(luhnValid("378282246310005"));
}

test "luhnValid rejects invalid sequences" {
    try std.testing.expect(!luhnValid("1234567890123456"));
    try std.testing.expect(!luhnValid("0000000000000001"));
    try std.testing.expect(!luhnValid(""));
}

test "unredact: empty input returns empty" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const out = try r.unredact(allocator, "");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "unredact: passthrough when no placeholders" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const out = try r.unredact(allocator, "no placeholders here, just text 123");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("no placeholders here, just text 123", out);
}

test "unredact: replaces single known email placeholder" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const redacted = try r.redact(allocator, "ping alice@acme.com today");
    defer allocator.free(redacted);
    try std.testing.expectEqualStrings("ping [EMAIL_1] today", redacted);

    const restored = try r.unredact(allocator, redacted);
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("ping alice@acme.com today", restored);
}

test "unredact: replaces multiple mixed-kind placeholders" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const redacted = try r.redact(allocator, "alice@acme.com / +7 905 123-45-67 / 4111111111111111");
    defer allocator.free(redacted);

    const restored = try r.unredact(allocator, redacted);
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("alice@acme.com / +7 905 123-45-67 / 4111111111111111", restored);
}

test "unredact: passes unknown placeholder verbatim" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const out = try r.unredact(allocator, "send to [EMAIL_99] now");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("send to [EMAIL_99] now", out);
}

test "unredact: ignores malformed bracket text" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const out = try r.unredact(allocator, "[email_1] [EMAIL_] [EMAIL_x] [oops] foo[bar");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("[email_1] [EMAIL_] [EMAIL_x] [oops] foo[bar", out);
}

test "unredact: same placeholder appearing twice maps to same original" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const redacted = try r.redact(allocator, "from alice@acme.com to alice@acme.com");
    defer allocator.free(redacted);
    try std.testing.expectEqualStrings("from [EMAIL_1] to [EMAIL_1]", redacted);

    const restored = try r.unredact(allocator, redacted);
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("from alice@acme.com to alice@acme.com", restored);
}

test "unredact: record_originals=false leaves placeholders intact" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{}); // default record_originals=false
    defer r.deinit();
    const redacted = try r.redact(allocator, "ping alice@acme.com");
    defer allocator.free(redacted);

    const restored = try r.unredact(allocator, redacted);
    defer allocator.free(restored);
    // No reverse map populated, so unredact is a no-op (placeholder unknown).
    try std.testing.expectEqualStrings("ping [EMAIL_1]", restored);
}

test "unredact: reset clears reverse map" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true });
    defer r.deinit();
    const before = try r.redact(allocator, "ping alice@acme.com");
    defer allocator.free(before);

    r.reset();

    const after = try r.unredact(allocator, before);
    defer allocator.free(after);
    // After reset the placeholder no longer resolves.
    try std.testing.expectEqualStrings("ping [EMAIL_1]", after);
}

test "unredact: max_originals bounds reverse map" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true, .max_originals = 1 });
    defer r.deinit();

    const redacted = try r.redact(allocator, "one a@b.co two x@y.zz");
    defer allocator.free(redacted);
    try std.testing.expectEqualStrings("one [EMAIL_1] two [EMAIL_2]", redacted);

    const restored = try r.unredact(allocator, redacted);
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("one a@b.co two [EMAIL_2]", restored);
}

test "Redactor max_identity_entries bounds placeholder maps" {
    // Regression: long-lived governance sessions must not grow HMAC identity
    // maps without bound under high-cardinality PII input.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .record_originals = true, .max_identity_entries = 1 });
    defer r.deinit();

    const first = try r.redact(allocator, "one a@b.co");
    defer allocator.free(first);
    try std.testing.expectEqualStrings("one [EMAIL_1]", first);

    const second = try r.redact(allocator, "two x@y.zz");
    defer allocator.free(second);
    try std.testing.expectEqualStrings("two [EMAIL_0]", second);
    try std.testing.expectEqual(@as(u32, 1), r.identityEntryCount());

    const repeated = try r.redact(allocator, "again a@b.co");
    defer allocator.free(repeated);
    try std.testing.expectEqualStrings("again [EMAIL_1]", repeated);

    const restored = try r.unredact(allocator, "known [EMAIL_1] capped [EMAIL_0]");
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("known a@b.co capped [EMAIL_0]", restored);
}

test "Redactor ISO datetime preserved - regression for #944" {
    // Regression: #944. Prompt timestamps must not be replaced with [PHONE_N].
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "Current time: 2026-06-02 20:17 UTC");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("Current time: 2026-06-02 20:17 UTC", out);
}

test "Redactor ISO datetime DD-MM-YYYY preserved" {
    // Regression: #944. Locale date/time strings can satisfy the phone heuristic.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "02-06-2026 20:17 UTC");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("02-06-2026 20:17 UTC", out);
}

test "Redactor full system date string preserved" {
    // Regression: #944. The full prompt date string must survive redaction.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "Tue Jun 02 2026-06-02 20:17:00 CST 2026");
    defer allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "PHONE") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "2026-06-02") != null);
}

test "Redactor phone still redacted alongside dates" {
    // Regression: #944 fix must not disable phone matches near date strings.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "at 2026-06-02 20:17 UTC call (202) 555-1234");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("at 2026-06-02 20:17 UTC call [PHONE_1]", out);
}

test "Redactor cron heartbeat timestamp preserved" {
    // Regression: #944. Heartbeat timestamps use the same false-positive shape.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator,
        \\ Heartbeat from bot at 2026-06-02 20:17 UTC
    );
    defer allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "PHONE") == null);
}

test "Redactor non-date hyphenated phone heuristic still redacts" {
    // Regression: date false-positive filtering must not treat every dddd- run
    // as a date and silently weaken the existing phone heuristic.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "call 1234-567-890 now");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("call [PHONE_1] now", out);
}

test "matchPlaceholderEnd: covers all kinds and rejects look-alikes" {
    try std.testing.expectEqual(@as(?usize, 9), matchPlaceholderEnd("[EMAIL_1]", 0));
    try std.testing.expectEqual(@as(?usize, 9), matchPlaceholderEnd("[PHONE_2]", 0));
    try std.testing.expectEqual(@as(?usize, 8), matchPlaceholderEnd("[CARD_3]", 0));
    try std.testing.expectEqual(@as(?usize, 6), matchPlaceholderEnd("[ID_7]", 0));
    try std.testing.expectEqual(@as(?usize, 9), matchPlaceholderEnd("[TOKEN_4]", 0));
    try std.testing.expectEqual(@as(?usize, null), matchPlaceholderEnd("[email_1]", 0));
    try std.testing.expectEqual(@as(?usize, null), matchPlaceholderEnd("[EMAIL_]", 0));
    try std.testing.expectEqual(@as(?usize, null), matchPlaceholderEnd("[EMAILX_1]", 0));
    try std.testing.expectEqual(@as(?usize, null), matchPlaceholderEnd("[EMAIL_1", 0));
    try std.testing.expectEqual(@as(?usize, null), matchPlaceholderEnd("EMAIL_1]", 0));
}
