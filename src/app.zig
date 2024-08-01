const std = @import("std");
const httpz = @import("httpz");
const logz = @import("logz");
const pg = @import("pg");
const zts = @import("zts");

const Allocator = std.mem.Allocator;

//------------------------------------------------------------------------------
// Init and deinit
const Self = @This();

allocator: Allocator = undefined,

pub fn init(allocator: Allocator) !Self {
    return .{
        .allocator = allocator,
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

    router.get("/", Self.index);

    // router.get("/login", Auth.loginHandler);
}

pub fn index(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = self; // autofix
    const tmpl = @embedFile("html/layouts/index.html");
    const w = res.writer();

    try zts.writeHeader(tmpl, w);

    // is logged in or not ?
    if (req.header("bearer") != null) {
        try zts.write(tmpl, "logged_in", w);
    } else {
        try zts.write(tmpl, "not_logged_in", w);
    }
}
