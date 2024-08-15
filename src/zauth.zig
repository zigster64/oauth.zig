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

pub fn authHandler(ctx: *SessionCtx, req: *httpz.Request, res: *httpz.Response) !void {
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

                // bump the expiry time to now + 30 seconds, and add it to the active session list
                pending_session.exp = std.time.timestamp() + 30;
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
