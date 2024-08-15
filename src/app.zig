const std = @import("std");
const httpz = @import("httpz");
const zul = @import("zul");
const logz = @import("logz");
const pg = @import("pg");
const zts = @import("zts");
const jwt = @import("jwt");

const zauth = @import("zauth.zig");
const middleware = @import("middleware.zig");

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

pub fn routes(self: *Self, router: anytype) void {
    _ = self;
    const sessionDispatch = .{ .dispatcher = middleware.dispatchWithSession };
    const htmx = .{ .dispatcher = middleware.htmxDispatch };
    const htmxProtected = .{ .dispatcher = middleware.htmxProtectedDispatch };

    router.getC("/", index, sessionDispatch);
    router.get("/zauth", zauth.authHandler);
    router.getC("/public", public, htmx);
    router.getC("/protected", protected, htmxProtected);
    // router.get("/login", Auth.loginHandler);
}

pub fn getSession(self: *Self, req: *httpz.Request, res: *httpz.Response) ?Session {
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
        // User has a cookie, but it doesnt match up with any known session at our end,
        // so be strict and just delete invalid cookie off the browser. Ouch !
        res.header("Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    }
    return null;
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

pub fn fullpage(self: *Self, req: *httpz.Request, res: *httpz.Response, ctx: SessionCtx) !void {
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

pub fn fullpage_end(_: *Self, req: *httpz.Request, res: *httpz.Response) void {
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

pub fn cleanupPendingSessions(self: *Self) void {
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
