# Method

The rule that makes a report worth paying for: **a claim and its grade travel
together.** Not in a footnote, not in a confidence column at the back — in the
same sentence.

## Grades

| grade | means | example |
|---|---|---|
| **Observed** | a tool printed it, verbatim | the disassembler shows `push <assert handler>` at the hit |
| **Derived** | follows from observed data by a stated rule | therefore this is an assertion macro, not a call |
| **Inferred** | a theory that fits the data, not proven | a packet that trips it probably crashes the process |
| **Unknown** | not established | whether any packet can reach it |

## Rules

1. Quote the tool and the call. "capstone, twelve instructions around the
   pointer hit" beats "the code appears to".
2. Addresses, not adjectives. `<address>`, not "somewhere in the binary".
3. Decompiler output is **derived**, never observed source.
4. If two tools disagree, say so and keep both.
5. Missing coverage is a finding. "Ghidra exceeded its import deadline on both
   binaries" belongs in the report, in the method section, in plain words.
6. An agent's confidence is not evidence. Only the tool output is.
7. A clean result is a result. "No key material found" is a finding and is
   published as one.

## The loop

```text
seed     one string, one call site, one feature name
trace    xrefs, pointer scan, search  -> a bounded set
read     disassemble or decompile      -> one unit at a time
state    what is proven, what is guessed, what is missing
repeat   a nil result is a result: record the dead end
```

## Why no numbers without measurement

A report may not contain a number the analysis did not produce. No "industry
standard", no "typically", no percentage that came from memory. If a figure
matters, it is measured or it is absent.

This is the same rule the trading desk in this workspace runs on: the code does
the arithmetic, and the writer may only cite the fact list. Anything else is
written as a rejected draft and never published.

## Hallucination guard

The known failure mode of agent-assisted reverse engineering is readable code
that is semantically wrong. Signs:

- the analysis explains a function it never opened;
- struct offsets do not add up;
- a "recovered" name is a guess dressed as a symbol;
- a test passes because the test was written from the same guess.

When any sign appears: stop, reopen the artifact, downgrade the claim to
inferred, and say so in the report.
