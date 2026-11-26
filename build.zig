const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The one exported module. Everything below is a developer step, so a
    // consumer's fetch graph stops at this module.
    const mod = b.addModule("sigv4", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (b.pkg_hash.len != 0) return;

    const test_step = b.step("test", "Run the unit tests, the AWS suite, and the guide's examples");

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    run_mod_tests.addPassthruArgs();
    test_step.dependOn(&run_mod_tests.step);

    // The AWS signing test suite and the reference vectors are read from disk
    // at run time, so the runner's working directory is the build root.
    const suite_mod = b.createModule(.{
        .root_source_file = b.path("test/suite.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sigv4", .module = mod }},
    });
    const suite_tests = b.addTest(.{ .root_module = suite_mod });
    const run_suite_tests = b.addRunArtifact(suite_tests);
    run_suite_tests.setCwd(b.path("."));
    // The run reads every fixture under its roots, which the build graph
    // cannot see, so a cached result would hide a new or changed case.
    run_suite_tests.has_side_effects = true;
    test_step.dependOn(&run_suite_tests.step);

    // The guide's examples are real programs against the public module,
    // tested with everything else so a guide page cannot show code that does
    // not build.
    const examples_mod = b.createModule(.{
        .root_source_file = b.path("docs/examples/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sigv4", .module = mod }},
    });
    const example_tests = b.addTest(.{ .root_module = examples_mod });
    const run_example_tests = b.addRunArtifact(example_tests);
    test_step.dependOn(&run_example_tests.step);
}
