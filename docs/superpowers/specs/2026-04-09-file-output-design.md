# File Output Option Design

**Date:** 2026-04-09  
**Feature:** Add `--output` option to write CLI output to a file in addition to stdout

---

## Summary

Add an optional `--output [<file>]` flag to `ssl-debugger`. When given, all output is written to both stdout and the specified file (same plain text format). If no filename is provided, a default name is generated. If the flag is omitted entirely, behavior is unchanged.

---

## CLI Option

```
--output [<file>]    Write output to file (default name: ssl-debug-<host>-<timestamp>.txt)
```

Behavior:
- `--output` omitted: no file written, stdout only (unchanged behavior)
- `--output result.txt`: output written to stdout and `result.txt`
- `--output` without a filename: output written to stdout and a default-named file in the current directory, e.g. `ssl-debug-example.com-20260409T143022.txt`

Implemented using picocli's `arity = "0..1"` with a `fallbackValue` sentinel to distinguish "not given" from "given without a filename".

---

## Architecture

### ResultPrinter refactor

`ResultPrinter` is refactored to accept a `PrintStream out` parameter added to the `print()` method signature instead of using `System.out` directly. All `System.out.println` / `System.out.printf` calls become `out.println` / `out.printf`.

### TeeOutputStream

A minimal `TeeOutputStream` is implemented locally in the project (no new dependency):

```java
class TeeOutputStream extends OutputStream {
    private final OutputStream a, b;
    TeeOutputStream(OutputStream a, OutputStream b) { this.a = a; this.b = b; }
    public void write(int c) throws IOException { a.write(c); b.write(c); }
    public void flush() throws IOException { a.flush(); b.flush(); }
    public void close() throws IOException { try { a.close(); } finally { b.close(); } }
}
```

### SslDebuggerCli.call() changes

A `buildOutputStream(String host, String outputOption)` helper determines the `PrintStream` to use:
- `--output` not given → `System.out`
- `--output <file>` or `--output` alone → `new PrintStream(new TeeOutputStream(System.out, new FileOutputStream(resolvedPath)))`

The file stream is managed in a try-with-resources block wrapping `printer.print(...)`.

---

## Error Handling

- If the output file cannot be opened (bad path, insufficient permissions): print an error to stderr and exit with a non-zero code **before** running the handshake probe — fail fast.
- After a successful run with file output: print a confirmation to stderr (not stdout, so it doesn't appear in the file): `Output written to: <path>`
- Exit codes are unchanged: `0` for handshake success, `1` for handshake failure.

---

## Testing

- Existing `ResultPrinterTest` can be updated to inject a `ByteArrayOutputStream` via the new `PrintStream` parameter, removing any dependency on `System.out`.
- New tests for `SslDebuggerCli` covering: no `--output`, `--output <file>`, `--output` without filename.
