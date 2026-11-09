const std = @import("std");

const android_targets = [_]struct { abi: []const u8, arch: std.Target.Cpu.Arch }{
    .{ .abi = "arm64-v8a", .arch = .aarch64 },
    .{ .abi = "x86_64", .arch = .x86_64 },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{ .abi = .none },
    });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const exe = addEngine(b, target, optimize, b.option(bool, "strip", "Strip debug info") orelse false);
    b.installArtifact(exe);

    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/vfs.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    const quota_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/quota.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(&b.addRunArtifact(quota_tests).step);

    // `zig build android` needs neither the NDK nor a libc: the engine is a
    // static binary that only talks to the kernel.
    const android = b.step("android", "Cross-compile static binaries for Android");
    for (android_targets) |t| {
        const resolved = b.resolveTargetQuery(.{ .cpu_arch = t.arch, .os_tag = .linux, .abi = .none });
        const android_exe = addEngine(b, resolved, .ReleaseSafe, true);
        const install = b.addInstallArtifact(android_exe, .{
            .dest_dir = .{ .override = .{ .custom = b.fmt("android/{s}", .{t.abi}) } },
        });
        android.dependOn(&install.step);
    }
}

fn addEngine(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: bool,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "pdock",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
        }),
    });
    // Newer Android devices run 16 KiB page kernels.
    exe.link_z_max_page_size = 16384;
    return exe;
}
