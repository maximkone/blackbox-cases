# 0002 — an app store client, end to end

| field | value |
|---|---|
| Artifact | F-Droid 2.0.2, `org.fdroid.fdroid`, 12,569,951 bytes |
| SHA-256 | `19d51fad482239f6df6a99120e34513667e9a86d136dafdc4a211a68c3327b52` |
| Provenance | public, GPLv3, downloaded from the project's own site |
| Date | 2026-10-26 |
| Scope | static: manifest, archive inventory, decompiled code. No device, no execution |
| Tools | artifact graph, a binary-AXML reader, jadx 1.5.6 |
| Findings | 5, of which 2 are policy rather than defects |

---

## Why this one is published

Because it came out **clean**, and a clean report is the hardest thing to fake.
Anyone can find something in a 12 MB app. Saying "no credentials, no TLS bypass,
no trackers, and here is exactly what that claim covers" is the product.

## The answer

An app store for free software: it fetches catalogues, verifies signatures and
hands packages to the system installer. 31 permissions, 36 components, 10
exported, and 11,950 decompiled files.

1. **No hardcoded credentials.** Zero private keys, zero API keys across every
   decompiled file. *(Observed.)*
2. **No TLS bypass.** The only `checkServerTrusted` call is okhttp's legitimate
   certificate-chain cleaner. No trust-all manager, no hostname-verifier
   override. *(Observed.)*
3. **Six exported components have no permission guard**, including three
   activity aliases that exist to disguise the app as a calculator in an
   emergency. *(Observed: `exported=true`, `permission=null`.)*
4. **No tracker SDKs.** Referenced hosts are the project's own, plus GitHub,
   GitLab and two donation platforms. *(Observed.)*
5. **The permission set is an installer's set** — `REQUEST_INSTALL_PACKAGES`,
   `UPDATE_PACKAGES_WITHOUT_USER_ACTION`, `QUERY_ALL_PACKAGES`,
   `MANAGE_EXTERNAL_STORAGE`, `WRITE_SETTINGS`. Correct for this distribution
   channel, fatal for the other one. *(Observed.)*

## The interesting finding

The disguise is launchable by any installed app. The calculator aliases are
exported with no permission, so a third-party app can start the disguise
directly, or detect that it is present by probing the component. For a panic
feature the trade-off is deliberate — this is a design note, not a defect, and
it is written as one.

That distinction is the whole job. A scanner reports "exported activity" as a
finding. A report says which exported activities are *supposed* to be exported
and why.

## Method, and the gap it left

1. Artifact graph: 851 nodes, 974 occurrences, 973 edges, every entry hashed.
2. Binary `AndroidManifest.xml` read directly from the string pool — no jadx, no
   apktool, no device.
3. jadx 1.5.6: 7,836 classes, 11,950 Java files, **147 decompile errors**.
4. A pattern scan for key material, TLS overrides, weak crypto, dynamic code,
   WebView bridges and referenced hosts.

**Not done:** no execution, no network capture, no APK Signing Block (v2/v3)
verification, and 147 classes were not decompiled. All four are printed in the
report rather than omitted.

## What a reader should take from it

- A manifest-only pass answers "what can this app do to my phone" and nothing
  more. That is a real product if it says so.
- A code pass answers "what does it actually contain". It is what finds secrets,
  and it is what says, credibly, that there are none.
- The number that matters in the method section is the one that looks bad: 147
  errors. A report without a number like that has not looked.

---

*Public artifact, analysed without client material. Reusable as a reference for
the method.*
