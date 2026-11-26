# Fixtures

Two roots and one runner, `test/suite.zig`. Both roots use the AWS signing test
suite's file layout: `request.txt` is the request as sent, `context.json` holds
the credentials and the time, and a `header-` or `query-` triple holds the
expected canonical request, string to sign, and signature. The runner reads the
files at run time and builds the signer's input from them.

- `aws-signing-suite/v4` is the official suite, copied unmodified from
  `awslabs/aws-c-auth` at the commit in [`../../THIRD_PARTY.md`](../../THIRD_PARTY.md).
  It is Apache-2.0, and its `LICENSE` and `NOTICE` are beside it.
- `vectors/v4` is seven cases for the shapes the suite does not have: an
  excluded header, duplicate header lines, an empty and a bare query
  parameter, a service path that needs a second escape, an S3 key holding a
  space, a plus, a percent, and an equals sign, and a session token.
  `generate.py` writes them with botocore, so the expected bytes come from a
  signer AWS ships. The S3 case is signed by `S3SigV4Auth`, records
  `"path_mode": "s3"` in its context, and carries `x-amz-content-sha256`.

Do not edit a vendored fixture. Add a vector through the generator instead.

No formatter opens these files. `just fmt` and `just lint` name `src`,
`test/suite.zig`, `test/examples.zig`, and `build.zig` for `zig fmt`, so the
fixture tree is never walked. `ziglint` reads `.zig` files only, `oxfmt` reads
`README.md`, `AGENTS.md`, and `.github`, and `nix fmt` reads Nix files.

Regenerate the vectors only when a shape changes:

```sh
nix shell --impure --expr \
  'with import (builtins.getFlake "nixpkgs") {}; python3.withPackages (ps: [ ps.botocore ])' \
  -c python3 test/fixtures/generate.py
```

Record the botocore version here and in `../../THIRD_PARTY.md` when you do.
