# sigv4: AWS Signature Version 4 request signing in Zig: the canonical request, the string to sign, and the HMAC-SHA256 signing key, with no I/O. `just --list` shows the recipes.
# AGENTS.md holds the working conventions.

[private]
default:
    @just --list

[doc("Unit tests, the AWS signing test suite and vectors, and the guide's examples")]
[group("test")]
test:
    zig build test --summary all

[doc("Lint Zig, Nix, Markdown, the workflows, and this justfile: ziglint, the shared ast-grep rules, zig fmt, nix fmt, oxfmt, actionlint, zizmor, and just --fmt")]
[group("lint")]
lint:
    ziglint-0-17
    baskingspot-lint src
    zig fmt --check src test/suite.zig test/examples.zig docs/examples build.zig build.zig.zon
    nix fmt -- --ci
    oxfmt --check README.md AGENTS.md CHANGELOG.md docs/content docs/config.toml .github .oxfmtrc.jsonc
    actionlint
    zizmor .
    just --fmt --check

[doc("Format everything lint checks")]
[group("lint")]
fmt:
    zig fmt src test/suite.zig test/examples.zig docs/examples build.zig build.zig.zon
    nix fmt
    oxfmt README.md AGENTS.md CHANGELOG.md docs/content docs/config.toml .github .oxfmtrc.jsonc
    just --fmt

[doc("The gate: the unit tests, the suite, and the guide's examples")]
[group("ci")]
check: test

[doc("Everything CI runs: the gate, lint, and the docs build")]
[group("ci")]
ci: check lint doc

[doc("Build the site into zig-out/site/sigv4/: the guide (Zola, from docs/) and the API reference (docgen JSON, rendered by the theme's api.html) under api/. The router in baskingspot/site serves /sigv4/... from it")]
[group("docs")]
doc: api
    baskingspot-docs build sigv4

[doc("Edit the guide with live reload (http://127.0.0.1:1111), API reference included")]
[group("docs")]
guide: api
    baskingspot-docs serve sigv4

# The API reference data. docgen comes from the baskingspot flake's docs shell,
# so this is not a Zig build dependency.
[private]
api:
    docgen --root src/root.zig --title sigv4 --repo-url https://github.com/baskingspot/sigv4 --rev main --format json --out docs/data

[doc("Deploy the rendered docs to Cloudflare as an assets-only Worker (config in wrangler.jsonc). Needs CLOUDFLARE_API_TOKEN in the environment, plus CLOUDFLARE_ACCOUNT_ID if the token can see more than one account")]
[group("docs")]
doc-deploy: doc
    wrangler deploy
