const std = @import("std");
const httpz = @import("httpz");
const logz = @import("logz");

const App = @import("app.zig");

pub fn main() !void {
    std.debug.print("All your {s} are belong to us.\n", .{"auth"});

    var gpa = std.heap.GeneralPurposeAllocator(.{ .verbose_log = false }){};
    const allocator = gpa.allocator();
    defer {
        if (gpa.deinit() != .ok) {
            logz.warn().boolean("memory_leak", true).src(@src()).log();
        }
    }
    // initialize a logging pool
    try logz.setup(allocator, .{
        .level = .Info,
        .pool_size = 100,
        .buffer_size = 8192,
        .large_buffer_count = 32,
        .large_buffer_size = 65536,
        .output = .stdout,
        // .encoding = .logfmt,
        .encoding = .json,
    });
    defer logz.deinit();

    var app = try App.init(allocator);
    defer app.deinit();

    // everything is setup - run us up a webserver then !
    const port = 8080;

    var server = try httpz.ServerApp(*App).init(allocator, .{
        .address = "0.0.0.0",
        .port = port,
    }, &app);
    const router = server.router();
    server.notFound(App.fileServer);
    server.dispatcher(App.logger);
    server.errorHandler(App.errorHandler);
    app.routes(router);
    logz.info().boolean("server_startup", true).int("port", port).log();
    std.debug.print("http://localhost:8080\n", .{});
    return server.listen();
}
