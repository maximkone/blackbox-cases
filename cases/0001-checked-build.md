# 0001 — live assertions in a shipped server binary

| field | value |
|---|---|
| Artifact | small native 32-bit game server, about 1 MB |
| Provenance | owner-supplied, redacted at his request |
| Date | 2026-10-26 |
| Scope | static only; no execution, no memory access, no client interaction |
| Tools | `pefile`, `capstone`, a pointer-scan script — no decompiler licence, no cloud upload |
| Findings | 1 confirmed, 1 located, 1 open question |
| Published | with the owner's permission, artifact unidentifiable |

---

## The question

The owner asked: *can people cheat on this server?* The useful answer turned out
to be about trust rather than cheating.

## What was done

Three steps, all offline:

1. Parsed the PE headers — sections, image base, where the code lives.
2. Found the strings that name the binary's own functions, then scanned for the
   raw 4-byte pointer to each one.
3. Disassembled twelve instructions around every hit.

Step three is where it paid. The string naming the experience-granting function
was referenced exactly once, and the code around it looked like this:

```asm
push  <expression text>
push  <line number>
push  <file name>
push  "<function name>"
push  5
push  <log destination>
call  <assert handler>
```

That is not a call. That is an **assertion macro**, compiled in and live.
*(Observed: the instruction sequence. Derived: it is an assert macro.)*

## Finding 1 — every live assertion is a crash primitive

If a remote packet can drive the process into a failing assertion, the server
goes down. No memory corruption, no exploit chain, no client modification — one
malformed message and a dead process, repeatable at will. *(Derived.)*

A release build compiles those checks out. This binary shipped from a checked
configuration. *(Observed: the macro is present. Inferred: it was not stripped
for release on purpose.)*

**Not established:** whether any single assertion is reachable from a packet.
Reachability needs the handler map, which was not built. *(Unknown — stated, not
guessed.)*

## Finding 2 — the administrative dispatcher is one region

The administrative command path has nine references clustered in a single
dispatcher region rather than scattered across the code. *(Observed.)*

One dispatcher and nine actions means one place decides who may do what. That is
either the best news in the file or the worst, and the answer is a privilege
check that has to be read to be believed.

**Not established:** whether any of the nine checks privilege before acting.
*(Unknown — needs function boundaries, which needs a decompiler.)*

## What the owner got

- A confirmed finding with the instruction sequence as evidence.
- The location of the administrative dispatcher, so the privilege review has a
  place to start.
- A three-step plan: map the packet handlers, check privilege per admin opcode,
  then decide which assertions to keep.
- An honest list of what was not established.

## What went wrong on the way

A pre-existing script of the owner's searched for a *call* to the
experience-granting function and found nothing. The reason is the finding: the
string is only ever an assertion message. A negative xref result is a fact about
the binary, not a failure of the search — and it is worth reporting as such.

A decompiler was attempted first and exceeded its import deadline on both this
binary and a larger one, on a loaded machine. The method above is what replaced
it: parse, scan for the pointer, disassemble around the hit. Slower to reason
with, faster to run, and enough to tell an assertion from a call.

## The general lesson

Server-authoritative design removes most cheats by construction: if the wire
carries inputs and never state, there is no field to send a teleport in. What
remains is not a cheat — it is **trust**: which inputs the server accepts, from
whom, and what it does when they are wrong.

Most small servers get the first part right by accident and the second part not
at all.
