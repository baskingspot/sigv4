# Signing benchmarks, 2026-11-26

Run id: `local-20261126-signing`.

Host: aarch64-linux-gnu, Neoverse V3. Zig 0.17.1, ReleaseFast through
testingx. `just bench -- --benchtime=200ms --count=5`, five rounds per row; the
numbers below are the runs the harness printed, and they did not move between
rounds. They are a regression baseline for this box, not a claim about another
host.

| Row | Work | ns/op |
| --- | --- | ---: |
| `CanonicalRequest` | `writeRequest` over 8 headers | 824 |
| `SigningKey` | the four HMACs, `scope` reused | 566 |
| `Authorization` | canonical request, key, string to sign, field | 2252 |
| `Presign` | canonical query, key, string to sign, query assembly | 2810 |

The key chain is about a quarter of the end-to-end cost; the rest is SHA-256
over the canonical request and the field or query assembly. A caller that signs
many requests for one scope hoists `signingKey` and pays roughly the difference
between `SigningKey` and `Authorization`.

The benchmark file is `src/bench.zig`; `just bench` drives it. The rows are
named after what they measure, so `just bench -- --filter=Authorization` runs
one of them.

```text
target: aarch64-linux-gnu
cpu: neoverse_v3
mode: fast
BenchmarkCanonicalRequest	  293316	       824.0 ns/op
BenchmarkCanonicalRequest	  290588	       825.0 ns/op
BenchmarkCanonicalRequest	  290853	       824.0 ns/op
BenchmarkCanonicalRequest	  291103	       824.0 ns/op
BenchmarkCanonicalRequest	  291051	       824.0 ns/op
BenchmarkSigningKey	  424003	       566.0 ns/op
BenchmarkSigningKey	  423908	       566.0 ns/op
BenchmarkSigningKey	  423996	       566.0 ns/op
BenchmarkSigningKey	  424863	       566.0 ns/op
BenchmarkSigningKey	  424087	       566.0 ns/op
BenchmarkAuthorization	  106645	      2251 ns/op
BenchmarkAuthorization	  106663	      2252 ns/op
BenchmarkAuthorization	  106532	      2252 ns/op
BenchmarkAuthorization	  106569	      2251 ns/op
BenchmarkAuthorization	  106480	      2252 ns/op
BenchmarkPresign	   85468	      2810 ns/op
BenchmarkPresign	   85398	      2810 ns/op
BenchmarkPresign	   85306	      2810 ns/op
BenchmarkPresign	   85393	      2810 ns/op
BenchmarkPresign	   85407	      2812 ns/op
```
