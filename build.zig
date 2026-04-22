const std = @import("std");

pub fn build(b: *std.Build) void {
    const main_file = b.path("src/main.zig");

    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const cModule = b.createModule(.{ .root_source_file = b.path("src/c.zig"), .target = target, .optimize = optimize });

    const mainModule = b.createModule(.{ .root_source_file = main_file, .target = target, .optimize = optimize });
    mainModule.addImport("c", cModule);
    const exe = b.addExecutable(.{ .name = "lan", .root_module = mainModule });

    const windowsTarget = b.resolveTargetQuery(std.Target.Query{
                // x86_64-windows-gnu
                .cpu_arch = .x86_64,
                .os_tag = .windows,
                .abi = .gnu,
            });
    const windowsModule = b.createModule(.{
            .root_source_file = main_file,
            .target = windowsTarget,
            .optimize = optimize
        });
    const windowsCModule = b.createModule(.{.root_source_file = b.path("src/c.zig"), .target = windowsTarget, .optimize = optimize});
    windowsModule.addImport("c", windowsCModule);
    const windowsExe = b.addExecutable(.{
        .name = "lan-win-x64",
        .root_module = windowsModule,
    });
    {
        windowsExe.linkLibC();
        const m = windowsCModule;

        // m.linkSystemLibrary("ws2_32", .{});
        // m.linkSystemLibrary("version", .{});
        // m.linkSystemLibrary("uuid", .{});
        // m.linkSystemLibrary("ole32", .{});

        // m.addIncludePath(b.path("deps/dummy/include"));

        // m.addSystemIncludePath(b.path("deps/windows/include"));
        // // m.addSystemIncludePath(b.path("deps/windows/sdk/include/um"));

        // m.addIncludePath(b.path("deps/npcap/Include/"));
        // m.addLibraryPath(b.path("deps/npcap/Lib"));

        m.addIncludePath(b.path("deps/WpdPack/Include"));
        // m.addLibraryPath(b.path("deps/WpdPack/Lib"));
        // m.addLibraryPath(b.path("deps/winpcap-dlls"));
        m.addLibraryPath(b.path("deps/npcap-lib/sysdlls"));
        // m.addObjectFile(b.path("deps/WpdPack/Lib/libwpcap.a"));
        // m.addObjectFile(b.path("deps/WpdPack/Lib/libpacket.a"));

        windowsExe.linkSystemLibrary("wpcap");
        windowsExe.linkSystemLibrary("Packet");
    }

    // TODO: this probably wouldn't work when building on windows native

    const exeInstall = b.addInstallArtifact(exe, .{});
    const windowsExeInstall = b.addInstallArtifact(windowsExe, .{});

    {
        const host_step = b.step("host", "Build for the host machine");
        host_step.dependOn(&exeInstall.step);

        const all_step = b.step("all", "Build all supported");
        all_step.dependOn(host_step);
        all_step.dependOn(&windowsExeInstall.step);
    }

    // i can't figure out how you're supposed to print in the build script?
    // std.debug.print("This will try to use sudo at some point. This is needed to allow running the final executable as non root\n", .{});
    // const addCapabilitiesRun = b.addSystemCommand(&.{"sudo"});
    // addCapabilitiesRun.addArgs(&.{ "setcap", "cap_net_admin,cap_net_raw=eip" });
    // addCapabilitiesRun.addArtifactArg(exe);
    // addCapabilitiesRun.expectExitCode(0);
    // b.getInstallStep().dependOn(&addCapabilitiesRun.step);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    // const run_cmd = b.addRunArtifact(exe);
    // sorry
    // const run_cmd = b.addSystemCommand(&.{"sudo"});
    // run_cmd.addArtifactArg(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    // run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    // if (b.args) |args| {
    //     run_cmd.addArgs(args);
    // }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    // const run_step = b.step("run", "Run the app");
    // run_step.dependOn(&run_cmd.step);

    const testModule = b.createModule(.{ .root_source_file = b.path("src/testroot.zig"), .target = target, .optimize = optimize });
    testModule.addImport("c", cModule);
    const exe_tests = b.addTest(.{ .root_module = testModule });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_tests.step);

    for ([_]*std.Build.Step.Compile{ exe, exe_tests }) |i| {
        i.linkLibC();
        i.linkSystemLibrary("pcap");
    }
}
