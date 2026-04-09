# SSL Handshake CLI Debugger

A Java CLI tool for diagnosing SSL/TLS handshake failures. It connects to a target host, captures the full JSSE debug output, and presents a structured step-by-step handshake trace alongside a human-readable summary.

## Features

- Step-by-step handshake trace: ClientHello, ServerHello, Certificate, Finished
- Human-readable summary for both success and failure (with error classification and fix hints)
- Optional full raw JSSE debug dump (`--raw`)
- Skip certificate validation (`--insecure`)
- HTTP proxy support via CONNECT tunnel (`--proxy`)
- Works with Java 17+ structured JSSE format and legacy Java 8–11 format

## Requirements

- Java 25 (to run the JAR)
- Gradle 9.4+ with Java 25 toolchain (to build)

## Build

```bash
./gradlew shadowJar
```

The fat JAR is produced at `app/build/libs/app.jar`.

## Usage

```
java -jar app/build/libs/app.jar --host <host> --port <port> [options]
```

| Option | Description |
|---|---|
| `--host` | Target hostname (required) |
| `--port` | Target port (required) |
| `--proxy` | HTTP proxy as `host:port` |
| `--insecure` | Skip certificate validation |
| `--raw` | Also print the full raw JSSE debug stream |
| `--help` | Show usage |
| `--version` | Show version |

## Examples

**Successful handshake:**
```bash
java -jar app/build/libs/app.jar --host example.com --port 443
```
```
=== TLS Handshake Trace ===

[1] ClientHello
    Offered protocols : TLSv1.3, TLSv1.2
    Offered cipher suites : TLS_AES_256_GCM_SHA384 ... (31 total)
    Extensions : server_name, supported_groups, signature_algorithms, supported_versions, key_share

[2] ServerHello
    Selected protocol : TLSv1.3
    Selected cipher suite : TLS_AES_256_GCM_SHA384

[3] Certificate
    Subject : CN=example.com
    Issuer  : CN=DigiCert TLS RSA SHA256 2020 CA1

[4] Finished
    Handshake complete

=== Summary ===
Host         : example.com:443
Status       : SUCCESS
Protocol     : TLSv1.3
Cipher Suite : TLS_AES_256_GCM_SHA384
Certificate  : CN=example.com (valid until 2025-01-15, 83 days remaining)
Chain depth  : 3
```

**Expired certificate:**
```bash
java -jar app/build/libs/app.jar --host expired.badssl.com --port 443
```
```
=== Summary ===
Host    : expired.badssl.com:443
Status  : FAILED
Error   : Certificate has expired
Hint    : Use --insecure to skip certificate validation
```

**Skip certificate validation:**
```bash
java -jar app/build/libs/app.jar --host self-signed.badssl.com --port 443 --insecure
```

**Through an HTTP proxy:**
```bash
java -jar app/build/libs/app.jar --host example.com --port 443 --proxy proxy.internal:8080
```

**Full raw JSSE debug output:**
```bash
java -jar app/build/libs/app.jar --host example.com --port 443 --raw
```

## Error Classification

The tool recognises common SSL failure patterns and provides targeted hints:

| Error | Hint |
|---|---|
| Certificate has expired | Use `--insecure` to skip validation |
| Untrusted certificate / unknown CA | Use `--insecure` or import the CA into your truststore |
| Hostname mismatch | Check the certificate's Subject Alternative Names |
| No shared cipher suites | Server may require legacy TLS configuration |
| Connection refused | Check host, port, and firewall settings |
| Connection timed out | Check host reachability |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Handshake succeeded |
| `1` | Handshake failed |

## Running Tests

```bash
./gradlew test
```

## Project Structure

```
app/src/main/java/net/cwnk/ssldebugger/
├── SslDebuggerCli.java       # picocli entry point
├── SslHandshakeProbe.java    # SSLSocket connection and handshake
├── JsseOutputCapture.java    # Redirects System.err to capture JSSE output
├── HandshakeStepParser.java  # Parses JSSE output into structured steps
├── HandshakeResult.java      # Immutable result record
├── HandshakeStep.java        # Single parsed handshake step
├── ResultPrinter.java        # Formats and prints output
└── TrustAllTrustManager.java # No-op TrustManager for --insecure mode
```
