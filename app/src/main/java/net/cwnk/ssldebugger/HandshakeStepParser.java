package net.cwnk.ssldebugger;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses JSSE debug output into discrete handshake steps.
 * Supports both the legacy format (Java 8–11: "*** ClientHello, ...")
 * and the structured format (Java 17+: "javax.net.ssl|DEBUG|...|Produced ClientHello...").
 */
public class HandshakeStepParser {

    // Java 17+ structured format: category|level|tid|thread|timestamp|source|message
    private static final Pattern JSSE_LINE = Pattern.compile(
            "^javax\\.net\\.ssl\\|\\w+\\|\\d+\\|[^|]+\\|[^|]+\\|[^|]+\\|(.+)$");

    public List<HandshakeStep> parse(String jsseOutput) {
        var steps = new ArrayList<HandshakeStep>();
        if (jsseOutput == null || jsseOutput.isBlank()) {
            return steps;
        }

        List<String> lines = jsseOutput.lines().toList();

        if (isStructuredFormat(lines)) {
            return parseStructured(lines);
        } else {
            return parseLegacy(lines);
        }
    }

    private boolean isStructuredFormat(List<String> lines) {
        return lines.stream().limit(20).anyMatch(l -> l.startsWith("javax.net.ssl|"));
    }

    // -------------------------------------------------------------------------
    // Structured format (Java 17+)
    // -------------------------------------------------------------------------

    private List<HandshakeStep> parseStructured(List<String> lines) {
        var steps = new ArrayList<HandshakeStep>();

        // Extract logical blocks: each block starts at a javax.net.ssl| line and
        // continues until the next such line.
        record Block(String header, List<String> body) {}
        var blocks = new ArrayList<Block>();
        String currentHeader = null;
        var currentBody = new ArrayList<String>();

        for (String line : lines) {
            if (line.startsWith("javax.net.ssl|")) {
                if (currentHeader != null) {
                    blocks.add(new Block(currentHeader, List.copyOf(currentBody)));
                }
                currentHeader = extractMessage(line);
                currentBody = new ArrayList<>();
            } else if (currentHeader != null) {
                currentBody.add(line);
            }
        }
        if (currentHeader != null) {
            blocks.add(new Block(currentHeader, List.copyOf(currentBody)));
        }

        // --- ClientHello ---
        blocks.stream()
                .filter(b -> b.header().contains("Produced ClientHello"))
                .findFirst()
                .ifPresent(b -> steps.add(buildClientHelloStructured(b.body())));

        // --- ServerHello ---
        blocks.stream()
                .filter(b -> b.header().contains("Consuming ServerHello"))
                .findFirst()
                .ifPresent(b -> {
                    // Also look for the separate "Negotiated protocol version" line
                    String negotiated = blocks.stream()
                            .filter(nb -> nb.header().contains("Negotiated protocol version"))
                            .findFirst()
                            .map(nb -> nb.header().replaceFirst(".*Negotiated protocol version:\\s*", "").trim())
                            .orElse(null);
                    steps.add(buildServerHelloStructured(b.body(), negotiated));
                });

        // --- Certificate ---
        blocks.stream()
                .filter(b -> b.header().contains("Consuming server Certificate"))
                .findFirst()
                .ifPresent(b -> steps.add(buildCertificateStructured(b.body())));

        // --- Finished ---
        boolean hasFinished = blocks.stream().anyMatch(b ->
                b.header().contains("Consuming server Finished") ||
                b.header().contains("Produced client Finished"));
        if (hasFinished) {
            steps.add(new HandshakeStep("Finished", List.of("Handshake complete")));
        }

        return steps;
    }

    private String extractMessage(String line) {
        Matcher m = JSSE_LINE.matcher(line);
        return m.matches() ? m.group(1) : line;
    }

    private HandshakeStep buildClientHelloStructured(List<String> body) {
        var details = new ArrayList<String>();

        // Supported versions from the extensions
        body.stream()
                .filter(l -> l.contains("\"versions\""))
                .findFirst()
                .ifPresent(l -> {
                    String v = l.replaceFirst(".*\"versions\"\\s*:\\s*", "").replaceAll("[\\[\\]]", "").trim();
                    details.add("Offered protocols : " + v);
                });

        // Cipher suites
        body.stream()
                .filter(l -> l.contains("\"cipher suites\""))
                .findFirst()
                .ifPresent(l -> {
                    // Extract the bracket content and count
                    String content = l.replaceFirst(".*\"cipher suites\"\\s*:\\s*\"\\[", "").replaceAll("].*", "");
                    String[] suites = content.split(",\\s*");
                    // Strip the hex codes: "TLS_AES_256_GCM_SHA384(0x1302)" → "TLS_AES_256_GCM_SHA384"
                    String first = suites[0].replaceAll("\\(0x[0-9A-Fa-f]+\\)", "").trim();
                    details.add("Offered cipher suites : " + first + " ... (" + suites.length + " total)");
                });

        // Extensions
        var extNames = new ArrayList<String>();
        boolean inExtensions = false;
        for (String l : body) {
            if (l.contains("\"extensions\"")) { inExtensions = true; continue; }
            if (inExtensions) {
                Matcher m = Pattern.compile("\"([a-z_]+) \\(\\d+\\)\"").matcher(l);
                if (m.find()) extNames.add(m.group(1));
            }
        }
        if (!extNames.isEmpty()) {
            details.add("Extensions : " + String.join(", ", extNames));
        }

        return new HandshakeStep("ClientHello", details);
    }

    private HandshakeStep buildServerHelloStructured(List<String> body, String negotiatedProtocol) {
        var details = new ArrayList<String>();

        String protocol = negotiatedProtocol;
        if (protocol == null) {
            // Try to get it from supported_versions extension in ServerHello body
            protocol = body.stream()
                    .filter(l -> l.contains("\"selected version\""))
                    .findFirst()
                    .map(l -> l.replaceFirst(".*\"selected version\"\\s*:\\s*\\[?", "").replaceAll("[\\])]", "").trim())
                    .orElse(null);
        }
        if (protocol != null) details.add("Selected protocol : " + protocol);

        body.stream()
                .filter(l -> l.contains("\"cipher suite\""))
                .findFirst()
                .ifPresent(l -> {
                    String cs = l.replaceFirst(".*\"cipher suite\"\\s*:\\s*\"", "")
                            .replaceAll("\\(0x[0-9A-Fa-f]+\\)", "")
                            .replaceAll("\".*", "").trim();
                    details.add("Selected cipher suite : " + cs);
                });

        return new HandshakeStep("ServerHello", details);
    }

    private HandshakeStep buildCertificateStructured(List<String> body) {
        var details = new ArrayList<String>();
        // Look for subject/issuer in the structured output
        for (String line : body) {
            String t = line.trim();
            if (t.startsWith("\"subject\"") || t.startsWith("subject:")) {
                details.add("Subject : " + t.replaceFirst(".*:", "").replaceAll("\"", "").trim());
            } else if (t.startsWith("\"issuer\"") || t.startsWith("issuer:")) {
                details.add("Issuer  : " + t.replaceFirst(".*:", "").replaceAll("\"", "").trim());
            } else if (t.contains("Not Before") || t.contains("Not After") || t.startsWith("\"not_before\"") || t.startsWith("\"not_after\"")) {
                details.add(t.replaceAll("\"", "").trim());
            }
        }
        return new HandshakeStep("Certificate", details);
    }

    // -------------------------------------------------------------------------
    // Legacy format (Java 8–11: "*** ClientHello, TLSv1.x")
    // -------------------------------------------------------------------------

    private List<HandshakeStep> parseLegacy(List<String> lines) {
        var steps = new ArrayList<HandshakeStep>();

        HandshakeStep clientHello = parseLegacyClientHello(lines);
        if (clientHello != null) steps.add(clientHello);

        HandshakeStep serverHello = parseLegacyServerHello(lines);
        if (serverHello != null) steps.add(serverHello);

        HandshakeStep certificate = parseLegacyCertificate(lines);
        if (certificate != null) steps.add(certificate);

        HandshakeStep finished = parseLegacyFinished(lines);
        if (finished != null) steps.add(finished);

        return steps;
    }

    private HandshakeStep parseLegacyClientHello(List<String> lines) {
        boolean inClientHello = false;
        var details = new ArrayList<String>();
        var cipherSuites = new ArrayList<String>();
        var extensions = new ArrayList<String>();
        String versions = null;
        boolean inCipherSuites = false;
        boolean inExtensions = false;

        for (String line : lines) {
            if (line.contains("*** ClientHello") || line.contains("ClientHello, TLS")) {
                inClientHello = true;
                continue;
            }
            if (!inClientHello) continue;
            if (line.contains("*** ServerHello") || line.contains("ServerHello, TLS")) break;

            String trimmed = line.trim();
            if (trimmed.startsWith("Versions:") || trimmed.contains("Supported Versions:")) {
                versions = trimmed;
            }
            if (trimmed.startsWith("Cipher Suites:") || trimmed.contains("cipher_suites")) {
                inCipherSuites = true;
                inExtensions = false;
            }
            if (trimmed.startsWith("Extensions:") || trimmed.startsWith("extensions:")) {
                inExtensions = true;
                inCipherSuites = false;
            }
            if (inCipherSuites && trimmed.startsWith("[") && trimmed.contains("TLS_")) {
                cipherSuites.add(trimmed.replaceAll("[\\[\\]\"{}]", "").trim());
            }
            if (inExtensions && !trimmed.isBlank() && !trimmed.startsWith("Extensions")) {
                extensions.add(trimmed.replaceAll("[\\[\\]\"{}]", "").trim());
            }
        }

        if (!inClientHello) return null;
        if (versions != null) details.add("Offered protocols : " + versions.replaceFirst(".*:", "").trim());
        if (!cipherSuites.isEmpty()) {
            details.add("Offered cipher suites : " + cipherSuites.get(0)
                    + (cipherSuites.size() > 1 ? " ... (" + cipherSuites.size() + " total)" : ""));
        }
        if (!extensions.isEmpty()) {
            details.add("Extensions : " + String.join(", ", extensions.subList(0, Math.min(extensions.size(), 5))));
        }
        return new HandshakeStep("ClientHello", details);
    }

    private HandshakeStep parseLegacyServerHello(List<String> lines) {
        boolean inServerHello = false;
        var details = new ArrayList<String>();
        String selectedProtocol = null;
        String selectedCipher = null;

        for (String line : lines) {
            if (line.contains("*** ServerHello") || line.contains("ServerHello, TLS")) {
                inServerHello = true;
                if (line.contains("TLSv")) {
                    int idx = line.indexOf("TLSv");
                    selectedProtocol = line.substring(idx).replaceAll("[,\\s].*", "").trim();
                }
                continue;
            }
            if (!inServerHello) continue;
            if (line.contains("*** Certificate") || line.contains("*** Finished") || line.contains("*** ServerHelloDone")) break;

            String trimmed = line.trim();
            if (trimmed.startsWith("CipherSuite:") || trimmed.startsWith("cipher_suite:")) {
                selectedCipher = trimmed.replaceFirst(".*:", "").trim();
            }
            if ((trimmed.startsWith("Protocol  :") || trimmed.startsWith("Protocol:")) && selectedProtocol == null) {
                selectedProtocol = trimmed.replaceFirst(".*:", "").trim();
            }
        }

        if (!inServerHello) return null;
        if (selectedProtocol != null) details.add("Selected protocol : " + selectedProtocol);
        if (selectedCipher != null) details.add("Selected cipher suite : " + selectedCipher);
        return new HandshakeStep("ServerHello", details);
    }

    private HandshakeStep parseLegacyCertificate(List<String> lines) {
        boolean inCert = false;
        var details = new ArrayList<String>();
        boolean addedOne = false;

        for (String line : lines) {
            if (line.contains("*** Certificate") || line.contains("chain [0]")) {
                inCert = true;
                continue;
            }
            if (!inCert) continue;
            if (addedOne && (line.contains("*** ") || line.contains("chain [1]"))) break;

            String trimmed = line.trim();
            if (trimmed.startsWith("Subject:") || trimmed.startsWith("subject:")) {
                details.add("Subject : " + trimmed.replaceFirst(".*:", "").trim());
                addedOne = true;
            }
            if (trimmed.startsWith("Issuer:") || trimmed.startsWith("issuer:")) {
                details.add("Issuer  : " + trimmed.replaceFirst(".*:", "").trim());
            }
            if (trimmed.startsWith("Validity") || trimmed.startsWith("Not Before") || trimmed.startsWith("Not After")) {
                details.add(trimmed);
            }
        }

        if (!inCert) return null;
        return new HandshakeStep("Certificate", details);
    }

    private HandshakeStep parseLegacyFinished(List<String> lines) {
        for (String line : lines) {
            if (line.contains("*** Finished") || line.contains("Finished message")
                    || line.contains("SESSION RESUMPTION") || line.contains("no resumption")) {
                return new HandshakeStep("Finished", List.of("Handshake complete"));
            }
        }
        for (String line : lines) {
            if (line.contains("WRITE: TLSv1.3") && line.contains("application_data")) {
                return new HandshakeStep("Finished", List.of("Handshake complete"));
            }
        }
        return null;
    }
}
