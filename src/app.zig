const std = @import("std");
const httpz = @import("httpz");
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
auth_url: ?[:0]const u8 = null,
client_id: ?[:0]const u8 = null,
client_secret: ?[:0]const u8 = null,
redirect_uri: ?[:0]const u8 = null,
scope: ?[:0]const u8 = null,
allocator: Allocator = undefined,

pub fn init(allocator: Allocator) !Self {
    const maybe_auth_url = std.posix.getenv("AUTH_URL");
    const maybe_client_id = std.posix.getenv("CLIENT_ID");
    const maybe_client_secret = std.posix.getenv("CLIENT_SECRET");
    const maybe_redirect_uri = std.posix.getenv("REDIRECT_URI");
    const maybe_scope = std.posix.getenv("SCOPE");

    return .{
        .allocator = allocator,
        .auth_url = maybe_auth_url,
        .client_id = maybe_client_id,
        .client_secret = maybe_client_secret,
        .redirect_uri = maybe_redirect_uri,
        .scope = maybe_scope,
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

    router.get("/", Self.index);
    router.getC("/public", Self.public, htmx);
    router.getC("/protected", Self.protected, htmx);

    // router.get("/login", Auth.loginHandler);
}

fn pageDispatcher(self: *Self, action: httpz.Action(*Self), req: *httpz.Request, res: *httpz.Response) !void {
    const t1 = std.time.microTimestamp();
    _ = t1; // autofix

    try self.fullpage(req, res);
    defer self.fullpage_end(req, res);

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
    const token = req.header("bearer") orelse {
        try self.login(req, res);
        return;
    };
    const w = res.writer();
    try w.print("Protected Content {s}", .{token});
}

pub fn login(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req; // autofix
    try zts.print(tmpl, "login", .{
        .auth_url = self.auth_url.?,
        .client_id = self.client_id.?,
        .redirect_uri = self.redirect_uri.?,
        .scope = self.scope.?,
        .state = "ABC123",
    }, res.writer());
}
