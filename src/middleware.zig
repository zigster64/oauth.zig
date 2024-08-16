const std = @import("std");
const httpz = @import("httpz");
const zul = @import("zul");
const logz = @import("logz");
const pg = @import("pg");
const zts = @import("zts");
const jwt = @import("jwt");

const App = @import("app.zig");

const Allocator = std.mem.Allocator;
const UUID = zul.UUID;

const Session = App.Session;
const SessionCtx = App.SessionCtx;

pub fn dispatchWithSession(self: *App, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
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

pub fn htmxDispatch(self: *App, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
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
            .string("user", ctx.session.name)
            .string("email", ctx.session.email);
    }

    l.int("duration_us", t2 - t1)
        .log();
}

pub fn htmxProtectedDispatch(self: *App, action: httpz.Action(*SessionCtx), req: *httpz.Request, res: *httpz.Response) !void {
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
        l = l.string("htmx🛡️", "hx-request");
    } else {
        l = l.string("htmx🛡️", "full-page");
    }
    l.string("session", &ctx.session.id.toHex(.lower))
        .string("user", ctx.session.name)
        .string("email", ctx.session.email)
        .int("duration_us", t2 - t1)
        .log();
}
