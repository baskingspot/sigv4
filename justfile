# sigv4: AWS Signature Version 4 request signing in Zig: the canonical request, the string to sign, and the HMAC-SHA256 signing key, with no I/O. `just --list` shows the recipes.
# AGENTS.md holds the working conventions.

[private]
default:
    @just --list

[doc("Unit tests")]
[group("test")]
test:
    zig build test --summary all

[doc("Lint Zig, Nix, Markdown, the workflows, and this justfile: ziglint, zig fmt, nix fmt, oxfmt, actionlint, zizmor, and just --fmt")]
[group("lint")]
lint:
    ziglint
    zig fmt --check src test/suite.zig test/examples.zig build.zig build.zig.zon
    nix fmt -- --ci
    oxfmt --check README.md AGENTS.md .github
    actionlint
    zizmor .
    just --fmt --check

[doc("Format everything lint checks")]
[group("lint")]
fmt:
    zig fmt src test/suite.zig test/examples.zig build.zig build.zig.zon
    nix fmt
    oxfmt README.md AGENTS.md .github
    just --fmt

[doc("Everything CI runs")]
[group("ci")]
ci: test lint
