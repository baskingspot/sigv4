# Reference vectors

The official suite has no case for a header the signer sees but must not sign,
duplicate header lines, an empty query parameter, a path that needs a second
escape, or a session token handed in as a credential. These five do, and
`test/suite.zig` runs them with the same code and the same file layout as the
suite in `../aws-signing-test-suite/v4`.

Each directory was written by `generate.py` with botocore 1.43.79, so the
expected canonical request, string to sign, signature, and `Authorization`
value come from a signer AWS ships rather than from this library. The
`session-token` case also reproduces the `get-vanilla-with-session-token`
signature from the official suite, which ties the two roots together.

Regenerate only when a shape changes:

```sh
nix shell --impure --expr \
  'with import (builtins.getFlake "nixpkgs") {}; python3.withPackages (ps: [ ps.botocore ])' \
  -c python3 tests/vectors/generate.py
```

Record the botocore version here and in `../../THIRD_PARTY.md` when you do.
