const std = @import("std");
const httpz = @import("httpz");
const zul = @import("zul");
const logz = @import("logz");
const pg = @import("pg");
const zts = @import("zts");
const jwt = @import("jwt");

const Allocator = std.mem.Allocator;
const UUID = zul.UUID;

//------------------------------------------------------------------------------
// values
const Self = @This();
const tmpl = @embedFile("html/layouts/index.html");

//------------------------------------------------------------------------------
// Session structs

pub const Session = struct {
    logged_in: bool = false,
    id: UUID = undefined, // unique ID per session
    url: []const u8 = undefined, // raw url of the request that created the session
    address: std.net.Address = undefined, // address of the client that created the session
    exp: i64 = 0, // expires
    first_name: ?[]const u8 = null,
    name: ?[]const u8 = null,
    email: ?[]const u8 = null,

    fn free(self: Session, allocator: Allocator) void {
        allocator.free(self.url);
        if (self.first_name) |first_name| allocator.free(first_name);
        if (self.name) |name| allocator.free(name);
        if (self.email) |email| allocator.free(email);
    }
};

pub const SessionCtx = struct {
    session: Session = Session{},
    app: *Self = undefined,
};

//------------------------------------------------------------------------------
// app struct values
auth_url: [:0]const u8 = undefined,
token_url: [:0]const u8 = undefined,
client_id: [:0]const u8 = undefined,
client_secret: [:0]const u8 = undefined,
redirect_uri: [:0]const u8 = undefined,
scope: [:0]const u8 = undefined,
jwt_secret: [:0]const u8 = undefined,
allocator: Allocator = undefined,
mutex: std.Thread.Mutex = std.Thread.Mutex{},

// In this implementation, all the sessions and pending sessions are in-memory only
// for a production app, you might want to keep it that way if you are running a single instance
// or you might want to store sessions in a DB instead ?

pending_sessions: std.ArrayList(Session) = undefined,
sessions: std.ArrayList(Session) = undefined,

pub fn init(allocator: Allocator) !Self {
    const maybe_auth_url = std.posix.getenv("AUTH_URL");
    const maybe_token_url = std.posix.getenv("TOKEN_URL");
    const maybe_client_id = std.posix.getenv("CLIENT_ID");
    const maybe_client_secret = std.posix.getenv("CLIENT_SECRET");
    const maybe_redirect_uri = std.posix.getenv("REDIRECT_URI");
    const maybe_scope = std.posix.getenv("SCOPE");
    const maybe_jwt_secret = std.posix.getenv("JWT_SECRET");

    return .{
        .allocator = allocator,
        .auth_url = maybe_auth_url.?,
        .token_url = maybe_token_url.?,
        .client_id = maybe_client_id.?,
        .client_secret = maybe_client_secret.?,
        .redirect_uri = maybe_redirect_uri.?,
        .scope = maybe_scope.?,
        .jwt_secret = maybe_jwt_secret.?,
        .pending_sessions = std.ArrayList(Session).init(allocator),
        .sessions = std.ArrayList(Session).init(allocator),
    };
}

pub fn deinit(self: Self) void {
    // free up any URLs stored in sessions
    for (self.pending_sessions.items) |v| {
        v.free(self.allocator);
    }
    self.pending_sessions.deinit();
    for (self.sessions.items) |v| {
        v.free(self.allocator);
    }
    self.sessions.deinit();
}

pub fn dispatch(self: *Self, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();

    var ctx = SessionCtx{
        .app = self,
    };
    try action(&ctx, req, res);
    const t2 = std.time.microTimestamp();
    logz.info()
        .string("protocol", @tagName(req.protocol))
        .string("method", @tagName(req.method))
        .string("url", req.url.raw)
        .int("duration_us", t2 - t1)
        .log();
}

pub fn dispatchGetSession(self: *Self, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();

    var ctx = SessionCtx{
        .session = self.getSession(req, res) orelse Session{},
        .app = self,
    };
    try action(&ctx, req, res);
    const t2 = std.time.microTimestamp();
    logz.info()
        .string("protocol", @tagName(req.protocol))
        .string("method", @tagName(req.method))
        .string("url", req.url.raw)
        .int("duration_us", t2 - t1)
        .log();
}

pub fn uncaughtError(self: *Self, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
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

pub fn notFound(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
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
    const sessionDispatch = .{ .dispatcher = Self.dispatchGetSession };
    const htmx = .{ .dispatcher = Self.htmxDispatch };
    const htmxProtected = .{ .dispatcher = Self.htmxProtectedDispatch };

    router.getC("/", index, sessionDispatch);
    router.get("/zauth", zauth);
    router.getC("/public", public, htmx);
    router.getC("/protected", protected, htmxProtected);
    // router.get("/login", Auth.loginHandler);
}

fn getSession(self: *Self, req: *httpz.Request, res: *httpz.Response) ?Session {
    const cookie = req.header("cookie");
    if (cookie != null and std.mem.eql(u8, cookie.?[0..8], "session=")) {
        const cookie_token = cookie.?[8..];
        const decoded = jwt.decode(
            req.arena,
            struct {
                email: []const u8,
                full_name: []const u8,
                first_name: []const u8,
                exp: i64,
                ip: []const u8,
                session: []const u8,
                url: []const u8,
            },
            cookie_token,
            .{ .secret = self.jwt_secret },
            .{},
        ) catch return null;
        {
            const claimed_session_id = UUID.parse(decoded.claims.session) catch return null;
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.sessions.items) |session| {
                if (session.id.eql(claimed_session_id)) {
                    return session;
                }
            }
        }
        res.header("Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    }
    return null;
}

fn htmxDispatch(self: *Self, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();
    defer self.fullpage_end(req, res);

    var ctx = SessionCtx{
        .session = self.getSession(req, res) orelse Session{},
        .app = self,
    };
    try self.fullpage(req, res, ctx);
    try action(&ctx, req, res);

    const t2 = std.time.microTimestamp();
    var l = logz.info()
        .string("protocol", @tagName(req.protocol))
        .string("method", @tagName(req.method))
        .string("url", req.url.raw);

    if (req.header("hx-request") != null) {
        l = l.string("htmx", "hx-request");
    } else {
        l = l.string("htmx", "full page");
    }

    if (ctx.session.logged_in) {
        l = l.string("session", &ctx.session.id.toHex(.lower))
            .string("user", ctx.session.email);
    }

    l.int("duration_us", t2 - t1)
        .log();
}

fn htmxProtectedDispatch(self: *Self, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();
    defer self.fullpage_end(req, res);

    var ctx = SessionCtx{
        .session = self.getSession(req, res) orelse {
            try self.fullpage(req, res, .{});
            return self.login(req, res);
        },
        .app = self,
    };
    try self.fullpage(req, res, ctx);
    try action(&ctx, req, res);

    const t2 = std.time.microTimestamp();
    var l = logz.info()
        .string("protocol", @tagName(req.protocol))
        .string("method", @tagName(req.method))
        .string("url", req.url.raw);

    if (req.header("hx-request") != null) {
        l = l.string("htmx ⛨", "hx-request");
    } else {
        l = l.string("htmx ⛨", "full page");
    }
    l.string("session", &ctx.session.id.toHex(.lower))
        .string("user", ctx.session.name)
        .int("duration_us", t2 - t1)
        .log();
}

pub fn index(ctx: *SessionCtx, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req; // autofix
    const w = res.writer();

    try zts.writeHeader(tmpl, w);

    // is logged in or not ?
    if (ctx.session.logged_in) {
        try zts.print(tmpl, "logged_in", .{ctx.session.first_name}, w);
    } else {
        try zts.write(tmpl, "not_logged_in", w);
    }

    try zts.write(tmpl, "links", w);
    try zts.write(tmpl, "content", w);
    try zts.write(tmpl, "end_content", w);
}

fn fullpage(self: *Self, req: *httpz.Request, res: *httpz.Response, ctx: SessionCtx) !void {
    _ = self; // autofix
    if (req.headers.get("hx-request") == null) {
        const w = res.writer();

        try zts.writeHeader(tmpl, w);

        // is logged in or not ?
        if (ctx.session.logged_in) {
            try zts.print(tmpl, "logged_in", .{ctx.session.first_name}, w);
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

pub fn public(ctx: *SessionCtx, req: *httpz.Request, res: *httpz.Response) !void {
    _ = ctx; // autofix
    _ = req; // autofix
    const w = res.writer();
    try w.writeAll("Public Content");
}

pub fn protected(ctx: *SessionCtx, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req; // autofix
    const w = res.writer();

    // middleware will redirect us to login page if they are not logged in
    try w.print("Some {s} content here", .{"secret"});
    try w.print("<br>", .{});
    try w.print("Your session ID is {s}", .{ctx.session.id});
}

fn cleanupPendingSessions(self: *Self) void {
    const now = std.time.timestamp();
    self.mutex.lock();
    defer self.mutex.unlock();
    for (self.pending_sessions.items, 0..) |pending_session, i| {
        if (pending_session.exp < now) {
            _ = self.pending_sessions.swapRemove(i);
            self.allocator.free(pending_session.url);
        }
    }
}

pub fn login(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    self.cleanupPendingSessions();

    const pending_session = Session{
        .logged_in = false,
        .id = UUID.v4(),
        .url = try self.allocator.dupe(u8, req.url.raw),
        .address = req.address,
        .exp = std.time.timestamp() + 30, // pending session is valid for 30 seconds only
    };

    self.mutex.lock();
    defer self.mutex.unlock();
    try self.pending_sessions.append(pending_session);

    // Session ID - pass this as the state param
    // IP of the client
    // path they want to go to
    // expires timestamp
    try zts.print(tmpl, "login", .{
        .auth_url = self.auth_url,
        .client_id = self.client_id,
        .redirect_uri = self.redirect_uri,
        .scope = self.scope,
        .state = pending_session.id,
        .path = pending_session.url,
    }, res.writer());
}

pub fn zauth(ctx: *SessionCtx, req: *httpz.Request, res: *httpz.Response) !void {
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
    const session_id = try UUID.parse(state);
    var maybe_session: ?*Session = null;

    const app = ctx.app;

    {
        app.cleanupPendingSessions();
        app.mutex.lock();
        defer app.mutex.unlock();

        for (app.pending_sessions.items, 0..) |*pending_session, i| {
            if (pending_session.id.eql(session_id)) {

                // remove the session from the pending session array
                _ = app.pending_sessions.swapRemove(i);

                // bump the expiry time to now + 1 hour, and add it to the active session list
                pending_session.exp = std.time.timestamp() + 3600;
                pending_session.logged_in = true;
                try app.sessions.append(pending_session.*);
                maybe_session = pending_session;
                break;
            }
        }
    }

    // TODO - if session not found, redirect them back to logout
    if (maybe_session == null) {
        logz.err()
            .string("session", &session_id.toHex(.lower))
            .log();
        return error.SessionNotFound;
    }
    var session = maybe_session.?;

    // check that the IP matches
    var req_address = req.address;
    req_address.setPort(0);
    var session_address = session.address;
    session_address.setPort(0);
    if (!req_address.eql(session_address)) {
        logz.err()
            .fmt("session_id", "{}", .{session.address})
            .fmt("real_ip", "{}", .{req.address})
            .log();
        return error.IPAddressMismatch;
    }

    // looks ok, so exchange the auth code for a token with the MS auth service
    var client = zul.http.Client.init(res.arena);
    defer client.deinit();

    var token_req = try client.request(app.token_url);
    defer token_req.deinit();

    try token_req.formBody("grant_type", "authorization_code");
    try token_req.formBody("client_id", app.client_id);
    try token_req.formBody("client_secret", app.client_secret);
    try token_req.formBody("code", code);
    try token_req.formBody("redirect_uri", app.redirect_uri);
    try token_req.formBody("state", state);
    token_req.method = .POST;

    var token_res = try token_req.getResponse(.{});

    if (token_res.status != 200) {
        res.status = 403;
        try res.writer().writeAll("Token Failed");
        return error.TokenFailed;
    }

    // TODO - the client has authenticated, we now have an access token and a refresh token
    // and a JWT with claims that include the email address, and the issuer
    // - delete the placeholder session
    // - create a real session, with a new session ID, client IP address, email
    // - create a JWT out of that, sign it, and send it back to the client as a new JWT token

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

    const decoded = try jwt.decode(
        res.arena,
        struct {
            aud: []const u8,
            iss: []const u8,
            appid: []const u8,
            name: []const u8,
            given_name: []const u8,
            unique_name: []const u8,
        },
        managed.value.access_token,
        .{ .secret = "" },
        .{ .skip_secret = true },
    );

    // TODO - verify that the appid from the token matches oun APPID

    // create a new session with the details, and use the sessionID in the new token we create
    var address_sb = zul.StringBuilder.init(res.arena);
    try address_sb.writer().print("{}", .{session.address});
    var my_ip_address = address_sb.string();
    if (std.mem.indexOf(u8, my_ip_address, ":")) |i| {
        my_ip_address = my_ip_address[0..i];
    }

    const new_token = try jwt.encode(
        res.arena,
        .{ .alg = .HS256 },
        .{
            .email = decoded.claims.unique_name,
            .full_name = decoded.claims.name,
            .first_name = decoded.claims.given_name,
            .exp = std.time.timestamp() + 36000, // 10 hours to expire
            .ip = my_ip_address,
            .session = session.id.toHex(.lower),
            .url = session.url,
        },
        .{ .secret = app.jwt_secret },
    );

    {
        app.mutex.lock();
        defer app.mutex.unlock();

        for (app.sessions.items) |*s| {
            if (s.id.eql(session.id)) {
                // fill in the missing details on the session
                s.first_name = try app.allocator.dupe(u8, decoded.claims.given_name);
                s.email = try app.allocator.dupe(u8, decoded.claims.unique_name);
                s.name = try app.allocator.dupe(u8, decoded.claims.name);
            }
        }
    }

    // set a cookie with the session, and redirect to the URL they originally asked for before being auth blocked
    res.status = 302;
    var sb = zul.StringBuilder.init(res.arena);
    try sb.writer().print("session={s}; HttpOnly; Path=/; Max-Age=36000", .{new_token});
    res.header("Set-Cookie", sb.string());
    res.header("Location", session.url);
}
