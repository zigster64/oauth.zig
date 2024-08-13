const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dep_opts = .{
        .target = target,
        .optimize = optimize,
    };

    const exe = b.addExecutable(.{
        .name = "oauth.zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    // add deps
    const httpz = b.dependency("httpz", dep_opts);
    exe.root_module.addImport("httpz", httpz.module("httpz"));

    const pg = b.dependency("pg", dep_opts);
    exe.root_module.addImport("pg", pg.module("pg"));

    const logz = b.dependency("logz", dep_opts);
    exe.root_module.addImport("logz", logz.module("logz"));

    const zul = b.dependency("zul", dep_opts);
    exe.root_module.addImport("zul", zul.module("zul"));

    const zts = b.dependency("zts", dep_opts);
    exe.root_module.addImport("zts", zts.module("zts"));

    const jwt = b.dependency("jwt", dep_opts);
    exe.root_module.addImport("jwt", jwt.module("jwt"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
