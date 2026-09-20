"""Repo symbol resolver — tree-sitter backed, language-agnostic.

Replaces vulnhuntr's jedi-only symbol_finder. Indexes every source file once:
function/class definitions (name -> snippet) and call sites inside each def.
Cross-file resolution = search all indexed defs (what jedi gives in practice).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from tree_sitter_language_pack import get_parser

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".go": "go", ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".rs": "rust", ".java": "java",
    ".rb": "ruby", ".php": "php", ".cs": "csharp", ".kt": "kotlin",
    ".swift": "swift", ".lua": "lua", ".scala": "scala",
}

DEF_NODES = {
    "python": {"function_definition", "class_definition"},
    "javascript": {"function_declaration", "method_definition", "class_declaration",
                   "generator_function_declaration", "arrow_function",
                   "function_expression", "variable_declarator"},
    "typescript": {"function_declaration", "method_definition", "class_declaration",
                   "arrow_function", "function_expression", "variable_declarator"},
    "tsx": {"function_declaration", "method_definition", "class_declaration",
            "arrow_function", "function_expression", "variable_declarator"},
    "go": {"function_declaration", "method_declaration", "type_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition", "class_specifier"},
    "rust": {"function_item", "struct_item", "impl_item"},
    "java": {"method_declaration", "class_declaration", "constructor_declaration",
             "interface_declaration"},
    "ruby": {"method", "class", "singleton_method"},
    "php": {"function_definition", "method_declaration", "class_declaration"},
    "csharp": {"method_declaration", "class_declaration", "constructor_declaration"},
    "kotlin": {"function_declaration", "class_declaration"},
    "swift": {"function_declaration", "class_declaration"},
    "lua": {"function_declaration", "function_definition"},
    "scala": {"function_definition", "class_definition"},
}
CALL_NODES = {"call", "call_expression", "function_call", "invocation_expression",
              "method_invocation", "call_expression"}
IDENT = {"identifier", "property_identifier", "type_identifier",
         "field_identifier", "constant", "simple_identifier", "scoped_identifier"}


@dataclass
class Snippet:
    file: str
    start: int
    end: int
    name: str
    text: str

    def fmt(self) -> str:
        return f"### {self.file}:{self.start}-{self.end}\n{self.text}"


class Resolver:
    def __init__(self, root: str | Path, max_defs: int = 40000):
        self.root = Path(root)
        self.defs: dict[str, list[Snippet]] = {}
        self.call_map: dict[str, list[str]] = {}   # "file:fn" -> callee names
        self.src_files: list[str] = []
        self._index(max_defs)

    # ---------- indexing ----------
    def _index(self, max_defs: int) -> None:
        files = subprocess.run(
            ["rg", "--files", "-0"], cwd=self.root,
            capture_output=True).stdout.decode().split("\0")
        for rel in files:
            if not rel or rel.startswith((".git/", "vendor/", "node_modules/",
                                          "dist/", "build/", "target/")):
                continue
            lang = EXT_LANG.get(Path(rel).suffix.lower())
            if not lang:
                continue
            try:
                src = (self.root / rel).read_bytes()
                parser = get_parser(lang)
            except Exception:
                continue
            self.src_files.append(rel)
            tree = parser.parse(src)
            self._walk(tree.root_node, rel, src, lang)
            if len(self.defs) > max_defs:
                return

    def _walk(self, node, rel: str, src: bytes, lang: str) -> None:
        if node.type in DEF_NODES.get(lang, set()):
            name = self._name_of(node, src)
            if name:
                text = src[node.start_byte:node.end_byte].decode(errors="replace")
                snip = Snippet(rel, node.start_point[0] + 1,
                               node.end_point[0] + 1, name, text)
                self.defs.setdefault(name, []).append(snip)
                callees: set[str] = set()
                for n in self._iter(node):
                    if n.type in CALL_NODES:
                        c = self._name_of(n, src) or self._last_ident(n, src)
                        if c:
                            callees.add(c)
                if callees:
                    self.call_map[f"{rel}:{name}"] = sorted(callees)
        for child in node.children:
            self._walk(child, rel, src, lang)

    @staticmethod
    def _iter(node):
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    @staticmethod
    def _name_of(node, src: bytes) -> str | None:
        for ch in node.children:
            if ch.type in IDENT:
                return src[ch.start_byte:ch.end_byte].decode(errors="replace")
            if ch.type == "function_declarator" or ch.type == "declarator":
                for g in ch.children:
                    if g.type in IDENT:
                        return src[g.start_byte:g.end_byte].decode(errors="replace")
        return None

    def _last_ident(self, node, src: bytes) -> str | None:
        name = None
        for n in self._iter(node):
            if n.type in IDENT:
                name = src[n.start_byte:n.end_byte].decode(errors="replace")
        return name

    # ---------- queries ----------
    def resolve(self, symbol: str, hint: str | None = None, k: int = 4) -> list[Snippet]:
        hits = self.defs.get(symbol, [])
        if not hits and "." in symbol:  # models ask for yaml.load; we index `load`
            hits = self.defs.get(symbol.rsplit(".", 1)[-1], [])
        if hint:
            hits = sorted(hits, key=lambda s: 0 if s.file == hint else 1)
        return hits[:k]

    def extract_fn(self, file: str, name: str) -> Snippet | None:
        for s in self.defs.get(name, []):
            if s.file == file:
                return s
        return None

    def calls_in(self, file: str, fn: str) -> list[str]:
        return self.call_map.get(f"{file}:{fn}", [])

    def window(self, file: str, line: int, pad: int = 30) -> str:
        try:
            lines = (self.root / file).read_text(errors="replace").splitlines()
        except Exception:
            return ""
        lo, hi = max(0, line - pad), min(len(lines), line + pad)
        return "\n".join(f"{i+1:>5} {l}" for i, l in enumerate(lines[lo:hi], lo))
