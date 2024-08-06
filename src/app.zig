const std = @import("std");
const httpz = @import("httpz");
const zul = @import("zul");
const logz = @import("logz");
const pg = @import("pg");
const zts = @import("zts");

const Allocator = std.mem.Allocator;

//------------------------------------------------------------------------------
// values
const Self = @This();
const tmpl = @embedFile("html/layouts/index.html");

//------------------------------------------------------------------------------
// app struct values
auth_url: [:0]const u8 = undefined,
token_url: [:0]const u8 = undefined,
client_id: [:0]const u8 = undefined,
client_secret: [:0]const u8 = undefined,
redirect_uri: [:0]const u8 = undefined,
scope: [:0]const u8 = undefined,
allocator: Allocator = undefined,

pub fn init(allocator: Allocator) !Self {
    const maybe_auth_url = std.posix.getenv("AUTH_URL");
    const maybe_token_url = std.posix.getenv("TOKEN_URL");
    const maybe_client_id = std.posix.getenv("CLIENT_ID");
    const maybe_client_secret = std.posix.getenv("CLIENT_SECRET");
    const maybe_redirect_uri = std.posix.getenv("REDIRECT_URI");
    const maybe_scope = std.posix.getenv("SCOPE");

    return .{
        .allocator = allocator,
        .auth_url = maybe_auth_url.?,
        .token_url = maybe_token_url.?,
        .client_id = maybe_client_id.?,
        .client_secret = maybe_client_secret.?,
        .redirect_uri = maybe_redirect_uri.?,
        .scope = maybe_scope.?,
    };
}

pub fn deinit(self: Self) void {
    _ = self; // autofix
}

pub fn logger(self: *Self, action: httpz.Action(*Self), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();

    try action(self, req, res);
    const t2 = std.time.microTimestamp();
    logz.info()
        .string("protocol", @tagName(req.protocol))
        .string("method", @tagName(req.method))
        .string("url", req.url.raw)
        .int("duration_us", t2 - t1)
        .log();
}

pub fn errorHandler(self: *Self, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
    _ = self;
    if (res.status == 0) {
        res.status = 500;
        res.body = "Internal Server Error";
    }

    logz.err()
        .int("status", res.status)
        .string("protocol", @tagName(req.protocol))
        .string("method", @tagName(req.method))
        .string("url", req.url.raw)
        .err(err)
        .log();
}

pub fn fileServer(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = self;
    errdefer {
        res.status = 404;
        res.body = "Not found";
    }

    // If the file exists in the public dir, then send it !
    const dir = try std.fs.cwd().openDir("www", .{});
    const file = try dir.openFile(req.url.path[1..], .{});
    defer file.close();

    res.body = try file.readToEndAlloc(req.arena, 1_000_000);
}

pub fn routes(self: *Self, router: anytype) void {
    _ = self;
    const htmx = .{ .dispatcher = Self.pageDispatcher };
    const htmxProtected = .{ .dispatcher = Self.pageDispatcherProtected };

    router.get("/", Self.index);
    router.get("/zauth", Self.zauth);
    router.getC("/public", Self.public, htmx);
    router.getC("/protected", Self.protected, htmxProtected);

    // router.get("/login", Auth.loginHandler);
}

fn pageDispatcher(self: *Self, action: httpz.Action(*Self), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();
    _ = t1; // autofix

    try self.fullpage(req, res);
    defer self.fullpage_end(req, res);

    try action(self, req, res);
}

fn pageDispatcherProtected(self: *Self, action: httpz.Action(*Self), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();
    _ = t1; // autofix

    try self.fullpage(req, res);
    defer self.fullpage_end(req, res);

    const cookie = req.header("cookie") orelse {
        // user is not logged in, so redirect to login page
        try self.login(req, res);
        return;
    };
    // std.debug.print("cookie is {s}\n", .{cookie});
    if (!std.mem.eql(u8, cookie[0..7], "bearer=")) {
        try self.login(req, res);
        return;
    }
    try action(self, req, res);
}

pub fn index(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = self; // autofix
    const w = res.writer();

    try zts.writeHeader(tmpl, w);

    // is logged in or not ?
    if (req.header("bearer") != null) {
        try zts.write(tmpl, "logged_in", w);
    } else {
        try zts.write(tmpl, "not_logged_in", w);
    }

    try zts.write(tmpl, "links", w);
    try zts.write(tmpl, "content", w);
    try zts.write(tmpl, "end_content", w);
}

fn fullpage(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = self; // autofix
    if (req.headers.get("hx-request") == null) {
        const w = res.writer();

        try zts.writeHeader(tmpl, w);

        // is logged in or not ?
        if (req.header("bearer") != null) {
            try zts.write(tmpl, "logged_in", w);
        } else {
            try zts.write(tmpl, "not_logged_in", w);
        }
        try zts.write(tmpl, "links", w);
    }
}

fn fullpage_end(_: *Self, req: *httpz.Request, res: *httpz.Response) void {
    if (req.headers.get("hx-request") == null) {
        const w = res.writer();

        zts.write(tmpl, "end_content", w) catch {};
    }
}

pub fn public(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = self; // autofix
    _ = req; // autofix
    const w = res.writer();
    try w.writeAll("Public Content");
}

pub fn protected(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req; // autofix
    _ = self; // autofix
    const w = res.writer();

    // middleware will redirect us to login page if they are not logged in
    try w.print("Some {s} content here", .{"secret"});
}

pub fn login(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req; // autofix
    try zts.print(tmpl, "login", .{
        .auth_url = self.auth_url,
        .client_id = self.client_id,
        .redirect_uri = self.redirect_uri,
        .scope = self.scope,
        .state = "ABC123",
    }, res.writer());
}

pub fn zauth(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    const query = try req.query();

    const maybe_code = query.get("code");
    const maybe_state = query.get("state");

    if (maybe_code == null or maybe_state == null) {
        res.status = 403;
        try res.writer().writeAll("Invalid Request");
        return error.InvalidRequest;
    }

    const code = maybe_code.?;
    const state = maybe_state.?;

    if (!std.mem.eql(u8, state, "ABC123")) {
        res.status = 403;
        try res.writer().writeAll("Incorrect State ?");
        return error.IncorrectState;
    }

    // looks ok, so exchange the auth code for a token with the MS auth service
    var client = zul.http.Client.init(res.arena);
    defer client.deinit();

    var token_req = try client.request(self.token_url);
    defer token_req.deinit();

    try token_req.formBody("grant_type", "authorization_code");
    try token_req.formBody("client_id", self.client_id);
    try token_req.formBody("client_secret", self.client_secret);
    try token_req.formBody("code", code);
    try token_req.formBody("redirect_uri", self.redirect_uri);
    try token_req.formBody("state", state);
    token_req.method = .POST;

    var token_res = try token_req.getResponse(.{});
    if (false) {
        const body = try token_res.allocBody(res.arena, .{});
        defer body.deinit();
        std.debug.print("got body {s}\n", .{body.string()});
    }

    if (token_res.status != 200) {
        std.debug.print("token res code {}\n", .{token_res.status});
        res.status = 403;
        try res.writer().writeAll("Token Failed");
        return error.TokenFailed;
    }

    const TokenResponse = struct {
        token_type: []const u8,
        access_token: []const u8,
        refresh_token: []const u8,
        id_token: []const u8,
        expires_in: u64,
        ext_expires_in: u64,
        scope: []const u8,
    };
    var managed = try token_res.json(TokenResponse, res.arena, .{});
    defer managed.deinit();

    res.status = 302;
    var sb = zul.StringBuilder.init(res.arena);
    // defer sb.deinit();
    try sb.write("bearer=");
    try sb.write(managed.value.access_token);
    // try sb.write("; HttpOnly; Secure; Path=/; Max-Age=3600");
    try sb.write("; HttpOnly; Path=/; Max-Age=3600");
    res.header("Set-Cookie", sb.string());
    res.header("Location", "/protected");

    std.debug.print("Logged in, with refresh token and id token\n{s}\n", .{managed.value.refresh_token});

    // const cookie = sb.string();
    // std.debug.print("Set cookie on zauth response to {s} len {d}\n", .{ cookie, cookie.len });

    // const redir = @embedFile("html/redirect.html");
    // const w = res.writer();
    // try zts.printHeader(redir, .{"/protected"}, w);
}
