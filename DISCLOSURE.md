# Disclosure policy

Short version: **we do not publish unpatched vulnerabilities in software we do
not own.**

## What gets published here

A case study may be published only when one of these is true:

1. The artifact is public and its owner has already published the issue, or
2. The owner has given written permission, and the case is redacted to the point
   where the artifact cannot be identified, or
3. 90 days have passed since the owner was notified, with no fix and no response.

Nothing else. A redacted case is still the owner's finding, and the owner is
told before the text is written.

## What is never published

- A working exploit, a PoC packet, or a reproduction script for an unpatched
  issue.
- An artifact, a hash, a virtual address or a path that identifies a private
  client's software.
- Anything a client marked confidential, for any length of time.
- Screenshots of a client's product without written permission.

## Redaction standard

A published case must not let a reader answer any of these:

- Which product is this?
- Which operator, studio or person is behind it?
- Can I find the binary from this text?

If a reader can answer any of the three, the redaction failed. Addresses become
`<address>`, sizes become "about 1 MB", names become "the experience-granting
function", and hashes are removed entirely.

## Reporting a problem in something we published

Open an issue, or use [SECURITY.md](SECURITY.md) for anything sensitive. If a
published case reveals something it should not, it is taken down first and
discussed second.

## Why this is written down

Because the alternative is a policy that lives in someone's head until the day
it matters. A one-person practice has no legal department; it has a rule it
wrote down in advance and a public record of following it.
