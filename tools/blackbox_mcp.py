#!/usr/bin/env python3
"""blackbox-mcp: give an AI agent two things it cannot do with a shell.

An MCP server (stdio, newline-delimited JSON-RPC) exposing:

  pe_xref        - find who references a string in a native PE, with disassembly
                   around each hit. No Ghidra, no IDA, no licence, no upload.
  pe_sections    - PE headers and section map.
  apk_manifest   - read a binary AndroidManifest.xml: package, SDK levels,
                   permissions, components, exported flags. No jadx, no device.
  binary_digest  - sha256, size, format.

Why it exists: an agent with a shell can run `strings`, and that is where it
stops. These three questions - who references this, what is in this manifest,
what is this file - are the first three of every reverse-engineering task, and
none of them is answerable with grep.

Read-only by construction: nothing here writes, executes or opens a handle to
a running process.

Deps: pefile, capstone (pip install pefile capstone)
Run:  python blackbox_mcp.py
"""
import hashlib
import json
import os
import struct
import sys
import zipfile

try:
    import capstone
    import pefile
except ImportError:  # keep the server alive so the error is visible to the client
    capstone = None
    pefile = None

SERVER_INFO = {"name": "blackbox", "version": "0.1.0"}
PROTOCOL = "2024-11-05"


# --------------------------------------------------------------------------- pe

def _load_pe(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = []
    for s in pe.sections:
        secs.append({
            "name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
            "va": base + s.VirtualAddress,
            "vsize": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "data": s.get_data(),
        })
    return pe, base, secs


def _string_sites(secs, needle):
    raw = needle.encode("ascii", "replace")
    out = []
    for s in secs:
        d = s["data"]
        i = d.find(raw)
        while i >= 0:
            j = i
            while j > 0 and d[j - 1] != 0:
                j -= 1
            out.append({"hit": s["va"] + i, "outer": s["va"] + j, "section": s["name"]})
            i = d.find(raw, i + 1)
    return out


def _ptr_sites(secs, va):
    needle = struct.pack("<I", va)
    out = []
    for s in secs:
        d = s["data"]
        i = d.find(needle)
        while i >= 0:
            out.append({"at": s["va"] + i, "section": s["name"]})
            i = d.find(needle, i + 1)
    return out


def _context(secs, site, back=24, count=12):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for s in secs:
        if not s["name"].startswith(".text"):
            continue
        lo, hi = s["va"], s["va"] + len(s["data"])
        if not (lo <= site < hi):
            continue
        start = max(lo, site - back)
        data = s["data"][start - lo: site - lo + 48]
        lines = []
        for ins in md.disasm(data, start):
            mark = " <<<" if ins.address <= site < ins.address + ins.size else ""
            lines.append(f"0x{ins.address:x}  {ins.mnemonic} {ins.op_str}{mark}")
            if len(lines) >= count:
                break
        return lines
    return []


def tool_pe_xref(args):
    path = args["path"]
    needles = args.get("needles") or []
    if not needles:
        return {"error": "needles must be a non-empty list of strings"}
    _pe, _base, secs = _load_pe(path)
    out = []
    for n in needles:
        sites = _string_sites(secs, n)
        entry = {"needle": n, "string_sites": [], "references": []}
        for st in sites:
            ptrs = _ptr_sites(secs, st["outer"])
            entry["string_sites"].append({
                "hit": hex(st["hit"]),
                "string_start": hex(st["outer"]),
                "section": st["section"],
                "pointer_sites": [hex(p["at"]) for p in ptrs],
            })
            for p in ptrs[:4]:
                entry["references"].append({
                    "site": hex(p["at"]),
                    "section": p["section"],
                    "disassembly": _context(secs, p["at"]),
                })
        out.append(entry)
    return {"path": path, "results": out}


def tool_pe_sections(args):
    pe, base, secs = _load_pe(args["path"])
    return {
        "path": args["path"],
        "image_base": hex(base),
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections": [
            {"name": s["name"], "va": hex(s["va"]), "vsize": s["vsize"], "raw_size": s["raw_size"]}
            for s in secs
        ],
    }


# -------------------------------------------------------------------------- apk

def _axml(raw):
    pool, out, off = [], [], 8
    while off + 8 <= len(raw):
        ctype, hsize, csize = struct.unpack_from("<HHI", raw, off)
        if csize == 0:
            break
        if ctype == 0x0001:
            count, _sc, flags, sstart, _st = struct.unpack_from("<IIIII", raw, off + 8)
            utf8 = bool(flags & 0x100)
            offs = struct.unpack_from("<%dI" % count, raw, off + hsize)
            base = off + sstart
            pool = []
            for o in offs:
                p = base + o
                if utf8:
                    n = raw[p]
                    p += 2 if n & 0x80 else 1
                    n = raw[p]
                    if n & 0x80:
                        n = ((n & 0x7F) << 8) | raw[p + 1]
                        p += 2
                    else:
                        p += 1
                    pool.append(raw[p:p + n].decode("utf-8", "replace"))
                else:
                    n = struct.unpack_from("<H", raw, p)[0]
                    p += 2
                    pool.append(raw[p:p + n * 2].decode("utf-16-le", "replace"))
        elif ctype == 0x0102:
            name_i = struct.unpack_from("<I", raw, off + hsize + 4)[0]
            astart, asize, acount = struct.unpack_from("<HHH", raw, off + hsize + 8)
            tag = pool[name_i] if name_i < len(pool) else "?"
            attrs = {}
            for i in range(acount):
                a = off + hsize + astart + i * asize
                ni, rawi = struct.unpack_from("<II", raw, a + 4)
                nm = pool[ni] if ni < len(pool) else "?"
                if rawi != 0xFFFFFFFF and rawi < len(pool):
                    attrs[nm] = pool[rawi]
                else:
                    _sz, _r, dt, val = struct.unpack_from("<HBBI", raw, a + 12)
                    if dt == 0x03:
                        attrs[nm] = pool[val] if val < len(pool) else None
                    elif dt == 0x12:
                        attrs[nm] = bool(val)
                    else:
                        attrs[nm] = val
            out.append((tag, attrs))
        off += csize
    return out


def tool_apk_manifest(args):
    path = args["path"]
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        elements = _axml(z.read("AndroidManifest.xml"))
    root, perms, comps, sdk = {}, [], [], {}
    for tag, a in elements:
        s = tag.rsplit(".", 1)[-1]
        if s == "manifest":
            root = {k: a.get(k) for k in ("package", "versionCode", "versionName", "compileSdkVersion")
                    if a.get(k) is not None}
        elif s in ("uses-permission", "uses-permission-sdk-23"):
            perms.append(a.get("name") or a.get("android:name"))
        elif s == "uses-sdk":
            for k in ("minSdkVersion", "targetSdkVersion", "android:minSdkVersion", "android:targetSdkVersion"):
                if a.get(k) is not None:
                    sdk["min" if "min" in k else "target"] = a[k]
        elif s in ("activity", "activity-alias", "service", "receiver", "provider"):
            comps.append({
                "type": s,
                "name": a.get("name") or a.get("android:name"),
                "exported": a.get("exported", a.get("android:exported")),
                "permission": a.get("permission") or a.get("android:permission"),
            })
    exported = [c for c in comps if c["exported"] is True]
    return {
        "path": path,
        "identity": root,
        "sdk": sdk,
        "permissions": [p for p in perms if p],
        "components_total": len(comps),
        "exported": exported,
        "exported_without_permission": [c for c in exported if not c["permission"]],
        "dex": sorted(n for n in names if n.endswith(".dex")),
        "abi": sorted({n.split("/")[2] for n in names if n.startswith("lib/") and n.count("/") >= 2}),
        "entries": len(names),
    }


def tool_binary_digest(args):
    path = args["path"]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    with open(path, "rb") as f:
        head = f.read(8)
    kind = "unknown"
    if head[:2] == b"MZ":
        kind = "pe"
    elif head[:4] == b"\x7fELF":
        kind = "elf"
    elif head[:4] == b"PK\x03\x04":
        kind = "zip-or-apk"
    elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        kind = "macho"
    return {"path": path, "sha256": h.hexdigest(), "bytes": os.path.getsize(path), "kind": kind}


TOOLS = {
    "pe_xref": {
        "fn": tool_pe_xref,
        "description": "Find who references a string in a native PE. Returns the "
                       "string site, every raw 4-byte pointer to it, and the "
                       "disassembly around each reference. No decompiler needed.",
        "schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "absolute path to the PE"},
                "needles": {"type": "array", "items": {"type": "string"},
                            "description": "strings to trace, e.g. a function name"},
            },
            "required": ["path", "needles"],
        },
    },
    "pe_sections": {
        "fn": tool_pe_sections,
        "description": "PE header facts: image base, machine, section map.",
        "schema": {"type": "object",
                   "properties": {"path": {"type": "string"}},
                   "required": ["path"]},
    },
    "apk_manifest": {
        "fn": tool_apk_manifest,
        "description": "Read an APK's binary AndroidManifest without jadx or a "
                       "device: package, SDK levels, permissions, components and "
                       "which exported components have no permission guard.",
        "schema": {"type": "object",
                   "properties": {"path": {"type": "string"}},
                   "required": ["path"]},
    },
    "binary_digest": {
        "fn": tool_binary_digest,
        "description": "SHA-256, size and format of a file. Use before any analysis.",
        "schema": {"type": "object",
                   "properties": {"path": {"type": "string"}},
                   "required": ["path"]},
    },
}


# ------------------------------------------------------------------------ mcp

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        method = msg.get("method")
        mid = msg.get("id")

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            }})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": n, "description": t["description"], "inputSchema": t["schema"]}
                for n, t in TOOLS.items()
            ]}})
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name")
            args = (msg.get("params") or {}).get("arguments") or {}
            tool = TOOLS.get(name)
            if not tool:
                send({"jsonrpc": "2.0", "id": mid,
                      "error": {"code": -32601, "message": f"unknown tool {name}"}})
                continue
            if pefile is None and name.startswith("pe_"):
                send({"jsonrpc": "2.0", "id": mid,
                      "error": {"code": -32000, "message": "pip install pefile capstone"}})
                continue
            try:
                result = tool["fn"](args)
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False,
                }})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                    "isError": True,
                }})
        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid,
                  "error": {"code": -32601, "message": f"unknown method {method}"}})


if __name__ == "__main__":
    main()
