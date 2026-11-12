"""Write docs/options.md from the option registry in config_schema.rs.

Usage: python3 script/docs/options-reference.py > docs/options.md
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = (ROOT / "lowertier/src/common/config_schema.rs").read_text(encoding="utf-8")

KIND = {
    "Bool": "bool", "Int": "integer", "Str": "string", "Path": "path",
    "StrList": "list of strings", "IntList": "list of integers",
    "Duration": "duration", "BitRate": "bit/s", "Bytes": "size",
    "Table": "table", "Tables": "array of tables",
}
APPLY = {
    "Live": "live", "NewConnections": "new connections",
    "QuicRestart": "new connections; QUIC: instance restart",
    "Restart": "instance restart", "Process": "process restart",
}


def skip_string(text, i):
    """Return the index just past the string literal that starts at text[i]."""
    j = i + 1
    while text[j] != '"':
        j += 2 if text[j] == "\\" else 1
    return j + 1


def split_args(text):
    args, depth, cur, i = [], 0, [], 0
    while i < len(text):
        c = text[i]
        if c == '"':
            j = skip_string(text, i)
            cur.append(text[i:j])
            i = j
            continue
        depth += c in "(["
        depth -= c in ")]"
        if c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def calls(text):
    for m in re.finditer(r"\b(opt|secret)\(", text):
        j, depth = m.end(), 1
        while depth:
            if text[j] == '"':
                j = skip_string(text, j)
                continue
            depth += text[j] == "("
            depth -= text[j] == ")"
            j += 1
        yield m.group(1), split_args(text[m.end():j - 1])


def unquote(s):
    assert s.startswith('"') and s.endswith('"'), s
    return bytes(s[1:-1], "utf-8").decode("unicode_escape")


consts = {name: re.findall(r'"([^"]*)"', body)
          for name, body in re.findall(r"const ([A-Z_]+): &\[&str\] = &\[([^\]]*)\];", SRC)}


def kind_text(kind):
    m = re.fullmatch(r"Enum\((.*)\)", kind, re.S)
    if m:
        inner = m.group(1).strip()
        values = consts.get(inner) or re.findall(r'"([^"]*)"', inner)
        return " \\| ".join(f"`{v}`" for v in values)
    if kind.startswith("Proxy("):
        return "host:port"
    return KIND[kind]


start = SRC.index("pub static OPTIONS: &[OptionSpec] = &[")
body = SRC[start:SRC.index("\n];", start)]
rows = []
for fn, args in calls(body):
    if fn == "opt":
        path, kind, _map, apply, default, doc = args
        rows.append((unquote(path), kind_text(kind), unquote(default), APPLY[apply], unquote(doc)))
    else:
        path, _map, apply, doc = args
        rows.append((unquote(path), "secret", "", APPLY[apply], unquote(doc)))

sections = {}
for row in rows:
    sections.setdefault(row[0].split(".")[0], []).append(row)

out = [
    "# Option reference",
    "",
    "Generated from the option registry in `lowertier/src/common/config_schema.rs` by `script/docs/options-reference.py`.",
    "`lowertier config explain PATH` prints the same text for one option.",
    "",
    "**Applies** says when a change to a running node takes effect: immediately (live), for new connections, after an instance restart, or after a process restart.",
    "Secrets are redacted in all output.",
    "",
]
for section, items in sections.items():
    nested = any("." in r[0] for r in items)
    title = f"`[{section}]`" if nested else f"`[[{section}]]`" if items[0][1] == "array of tables" else f"`[{section}]`"
    out += [f"## {title}", "", "| Option | Type | Default | Applies | What it does |", "| --- | --- | --- | --- | --- |"]
    for path, kind, default, apply, doc in items:
        shown = f"`{default}`" if default else ""
        out.append(f"| `{path}` | {kind} | {shown} | {apply} | {doc.replace('|', chr(92) + '|')} |")
    out.append("")
sys.stdout.write("\n".join(out))
print(f"{len(rows)} options", file=sys.stderr)
