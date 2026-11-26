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

    // testingx provides the test runner. It is lazy because only the root
    // build uses it; a consumer never fetches it. On the first configure pass
    // it is not fetched yet, `dependencyLazy` returns null, and the build
    // runner fetches it and reruns this script.
    const testingx_dep = (b.dependencyLazy("testingx", .{ .target = target }) catch null);
    const test_runner: ?std.Build.Step.Compile.TestRunner = if (testingx_dep) |dep|
        .{ .path = dep.path("src/runner.zig"), .mode = .simple }
    else
        null;

    const test_step = b.step("test", "Run the unit tests, the AWS suite, and the README example");

    const mod_tests = b.addTest(.{
        .root_module = mod,
        .test_runner = test_runner,
    });
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
    const suite_tests = b.addTest(.{
        .root_module = suite_mod,
        .test_runner = test_runner,
    });
    const run_suite_tests = b.addRunArtifact(suite_tests);
    run_suite_tests.setCwd(b.path("."));
    // The run reads every fixture under its roots, which the build graph
    // cannot see, so a cached result would hide a new or changed case.
    run_suite_tests.has_side_effects = true;
    test_step.dependOn(&run_suite_tests.step);

    // The README's example and the public-surface checks are compiled against
    // the module with everything else, so the README cannot show code that
    // does not build.
    const examples_mod = b.createModule(.{
        .root_source_file = b.path("test/examples.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sigv4", .module = mod }},
    });
    const example_tests = b.addTest(.{
        .root_module = examples_mod,
        .test_runner = test_runner,
    });
    const run_example_tests = b.addRunArtifact(example_tests);
    test_step.dependOn(&run_example_tests.step);

    // The guide's examples: the code docs/content shows, compiled against the
    // public module so a guide page cannot show code that does not build.
    const guide_mod = b.createModule(.{
        .root_source_file = b.path("docs/examples/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sigv4", .module = mod }},
    });
    const guide_tests = b.addTest(.{
        .root_module = guide_mod,
        .test_runner = test_runner,
    });
    const run_guide_tests = b.addRunArtifact(guide_tests);
    test_step.dependOn(&run_guide_tests.step);
}
