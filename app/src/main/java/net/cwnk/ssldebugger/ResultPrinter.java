package net.cwnk.ssldebugger;

import java.io.PrintStream;
import java.net.SocketTimeoutException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;

public class ResultPrinter {

    public void print(HandshakeResult result, String rawJsseOutput, List<HandshakeStep> steps, boolean raw, PrintStream out) {
        printHandshakeTrace(result, steps, out);
        if (raw) {
            printRawOutput(rawJsseOutput, out);
        }
        printSummary(result, out);
    }

    private void printHandshakeTrace(HandshakeResult result, List<HandshakeStep> steps, PrintStream out) {
        out.println();
        out.println("=== TLS Handshake Trace ===");
        out.println();

        if (steps.isEmpty()) {
            out.println("(Handshake steps could not be parsed — use --raw to see full output)");
        } else {
            for (int i = 0; i < steps.size(); i++) {
                HandshakeStep step = steps.get(i);
                out.printf("[%d] %s%n", i + 1, step.name());
                if ("Certificate".equals(step.name())) {
                    printCertificateChain(result.peerCertificates(), out);
                } else {
                    for (String detail : step.details()) {
                        out.println("    " + detail);
                    }
                }
                out.println();
            }
        }
    }

    private void printCertificateChain(X509Certificate[] certs, PrintStream out) {
        if (certs == null || certs.length == 0) {
            out.println("    (no certificate data available)");
            return;
        }
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = certs[i];
            String role = certRole(cert, i, certs.length);
            out.printf("    [%d] %s%n", i + 1, role);
            out.println("        Subject : " + cert.getSubjectX500Principal().getName());
            out.println("        Issuer  : " + cert.getIssuerX500Principal().getName());
            out.println("        Serial  : " + formatSerial(cert));
            LocalDate notBefore = cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            LocalDate notAfter  = cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            out.println("        Valid   : " + notBefore + " → " + notAfter);
        }
    }

    private String certRole(X509Certificate cert, int index, int total) {
        if (index == 0) return "Server Certificate";
        boolean selfSigned = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (selfSigned) return "Root CA";
        return "Intermediate CA";
    }

    private String formatSerial(X509Certificate cert) {
        String hex = cert.getSerialNumber().toString(16).toUpperCase();
        if (hex.length() % 2 != 0) hex = "0" + hex;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (!sb.isEmpty()) sb.append(':');
            sb.append(hex, i, i + 2);
        }
        return sb.toString();
    }

    private void printRawOutput(String rawJsseOutput, PrintStream out) {
        out.println("=== Raw JSSE Debug Output ===");
        out.println();
        out.println(rawJsseOutput);
        out.println();
    }

    private void printSummary(HandshakeResult result, PrintStream out) {
        out.println("=== Summary ===");
        out.printf("%-13s: %s%n", "Host", result.host() + ":" + result.port());

        if (result.success()) {
            out.printf("%-13s: SUCCESS%n", "Status");
            out.printf("%-13s: %s%n", "Protocol", result.protocol());
            out.printf("%-13s: %s%n", "Cipher Suite", result.cipherSuite());

            X509Certificate[] certs = result.peerCertificates();
            if (certs != null && certs.length > 0) {
                X509Certificate leaf = certs[0];
                String subject = leaf.getSubjectX500Principal().getName();
                LocalDate notAfter = leaf.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                long daysRemaining = ChronoUnit.DAYS.between(LocalDate.now(), notAfter);
                out.printf("%-13s: %s (valid until %s, %d days remaining)%n",
                        "Certificate", subject, notAfter, daysRemaining);
                out.printf("%-13s: %d%n", "Chain depth", certs.length);
            }
        } else {
            out.printf("%-13s: FAILED%n", "Status");
            Exception ex = result.exception();
            ErrorInfo info = classifyError(ex);
            out.printf("%-13s: %s%n", "Error", info.message());
            if (info.detail() != null) {
                out.printf("%-13s: %s%n", "Detail", info.detail());
            }
            if (info.hint() != null) {
                out.printf("%-13s: %s%n", "Hint", info.hint());
            }
        }
        out.println();
    }

    private ErrorInfo classifyError(Exception ex) {
        if (ex == null) return new ErrorInfo("Unknown error", null, null);

        String msg = ex.getMessage() != null ? ex.getMessage() : "";
        Throwable cause = ex.getCause();
        String causeMsg = cause != null && cause.getMessage() != null ? cause.getMessage() : "";
        String combined = msg + " " + causeMsg;

        if (combined.contains("certificate_expired") || combined.contains("NotAfter") || combined.contains("expired")) {
            return new ErrorInfo("Certificate has expired",
                    extractNotAfter(combined),
                    "Use --insecure to skip certificate validation");
        }
        if (combined.contains("PKIX path") || combined.contains("unable to find valid certification path")) {
            return new ErrorInfo("Untrusted certificate / unknown CA",
                    "The server's certificate chain could not be verified against trusted CAs",
                    "Use --insecure to skip validation, or import the CA certificate into your truststore");
        }
        if (combined.contains("No name matching") || combined.contains("No subject alternative")) {
            return new ErrorInfo("Hostname mismatch",
                    msg,
                    "Check the certificate's Subject Alternative Names (SANs)");
        }
        if (combined.contains("no cipher suites in common") || combined.contains("no cipher")) {
            return new ErrorInfo("No shared cipher suites",
                    "Client and server could not agree on a common cipher suite",
                    "The server may require legacy TLS configuration");
        }
        if (ex instanceof java.net.ConnectException || combined.contains("Connection refused")) {
            return new ErrorInfo("Connection refused",
                    "Could not connect to " + combined.replaceFirst(".*Connection refused.*", "").trim(),
                    "Check host, port, and firewall settings");
        }
        if (ex instanceof SocketTimeoutException || combined.contains("timed out")) {
            return new ErrorInfo("Connection timed out",
                    null,
                    "Check host reachability and network connectivity");
        }
        return new ErrorInfo(msg.isEmpty() ? ex.getClass().getSimpleName() : msg, null, null);
    }

    private String extractNotAfter(String text) {
        int idx = text.indexOf("NotAfter:");
        if (idx >= 0) {
            return text.substring(idx, Math.min(text.length(), idx + 60)).trim();
        }
        return null;
    }

    private record ErrorInfo(String message, String detail, String hint) {}
}
