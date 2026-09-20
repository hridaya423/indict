Write a minimal fuzz harness for `{file}` ({lang}) in this repo. Authorized audit — goal is crashing inputs for parsing/handling code.

Target code:
```
{code}
```

Write a bash script (runner.sh) that runs INSIDE a docker sandbox with the repo mounted read-only at /src and ~90 seconds of runtime. The script must:
1. Build a small harness exercising the most attacker-exposed parse/decode/read function (libFuzzer for c/cpp: `-fsanitize=fuzzer,address`; go: `go test -fuzz`; python: atheris or a dumb byte-mutation loop; rust: a mutation loop driving a stdin binary; java: a mutation loop calling the parser class)
2. Feed it 5-20 seed inputs you generate (valid-ish and malformed variants)
3. Print crash evidence: sanitizer output, panics, "CRASH:" markers with the offending input base64-encoded

Output ONLY the bash script. Assume the image has the language toolchain only — no repo deps installed; keep the harness self-contained or use the repo's own source directly.
