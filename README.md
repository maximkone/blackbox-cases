# Blackbox — case studies

Public write-ups of binary and application analysis: what was examined, what was
found, and — the part most reports leave out — what was not established.

This repository is the public face of a one-person analysis practice. It exists
so that a prospective client can read the work before paying for it, and so that
every claim in a paid report can be checked against a published example of the
same method.

## Case studies

| # | artifact | type | findings |
|---|---|---|---|
| [0001](cases/0001-checked-build.md) | small native game server, ~1 MB, redacted | static, no decompiler | live assertions in a shipped binary; admin dispatcher located |
| [0002](cases/0002-android-teardown.md) | open-source Android app, 12.6 MB, public | manifest + decompiled code | 6 unguarded exported components; no key material; no TLS bypass |

## Tools

**[blackbox-mcp](tools/blackbox_mcp.py)** — an MCP server that gives an AI agent
four things a shell cannot:

| tool | answers |
|---|---|
| `pe_xref` | who references this string in a native PE — with disassembly around each hit |
| `pe_sections` | image base, machine, section map |
| `apk_manifest` | package, SDK levels, permissions, components, exported-without-permission |
| `binary_digest` | sha256, size, format — before any analysis |

No Ghidra. No IDA. No jadx. No device. No upload. Read-only by construction:
nothing here writes, executes, or opens a handle to a running process.

```bash
pip install pefile capstone
python tools/blackbox_mcp.py        # stdio MCP
```

Why it exists: an agent with a shell can run `strings`, and that is where it
stops. "Who references this", "what is in this manifest", "what is this file" are
the first three questions of every reverse-engineering task, and grep answers
none of them.

## How the work is described

Every claim carries one of four grades, in the same line as the claim:

- **Observed** — a tool printed it, verbatim.
- **Derived** — follows from observed data by a stated rule.
- **Inferred** — a theory that fits the data, not proven.
- **Unknown** — not established.

See [METHOD.md](METHOD.md). The grades are not decoration: they are the
difference between a report and a guess with good manners.

## What this is not

- Not a vulnerability disclosure channel. See [DISCLOSURE.md](DISCLOSURE.md).
- Not a bug-bounty program. There is no reward here.
- Not a claim of completeness. Each case states its own limits.

## Commissioning work

Fixed scope, fixed price, named turnaround. The scope page goes out before any
file is opened, and no file is opened until it comes back signed. Start an
[issue](../../issues) with the artifact type and the decision you need to make;
that is enough for a first reply.

## Licence

Text and case studies: [CC BY 4.0](LICENSE). Tooling referenced here is
Apache-2.0. Third-party artifacts remain under their own licences and are never
redistributed.

## Corrections

If something here is wrong, open an issue. Corrections are published with the
date and the change, not silently edited. A research practice that cannot show
its corrections has no method.
