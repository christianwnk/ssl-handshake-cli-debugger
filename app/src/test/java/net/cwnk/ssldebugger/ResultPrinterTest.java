package net.cwnk.ssldebugger;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ResultPrinterTest {

    private final ResultPrinter printer = new ResultPrinter();

    private String captureOutput(Runnable action) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream old = System.out;
        System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
        try {
            action.run();
        } finally {
            System.setOut(old);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    @Test
    void successSummaryContainsKeyFields() {
        HandshakeResult result = HandshakeResult.success("example.com", 443, "TLSv1.3", "TLS_AES_256_GCM_SHA384", null);
        String output = captureOutput(() -> printer.print(result, "", List.of(), false));
        assertTrue(output.contains("SUCCESS"));
        assertTrue(output.contains("example.com:443"));
        assertTrue(output.contains("TLSv1.3"));
        assertTrue(output.contains("TLS_AES_256_GCM_SHA384"));
    }

    @Test
    void failureSummaryContainsFailedStatus() {
        HandshakeResult result = HandshakeResult.failure("badhost.example", 443, new RuntimeException("Connection refused"));
        String output = captureOutput(() -> printer.print(result, "", List.of(), false));
        assertTrue(output.contains("FAILED"));
        assertTrue(output.contains("badhost.example:443"));
    }

    @Test
    void rawOutputPrintedWhenFlagSet() {
        HandshakeResult result = HandshakeResult.success("example.com", 443, "TLSv1.3", "TLS_AES_256_GCM_SHA384", null);
        String output = captureOutput(() -> printer.print(result, "raw jsse content here", List.of(), true));
        assertTrue(output.contains("Raw JSSE Debug Output"));
        assertTrue(output.contains("raw jsse content here"));
    }

    @Test
    void rawOutputNotPrintedWhenFlagNotSet() {
        HandshakeResult result = HandshakeResult.success("example.com", 443, "TLSv1.3", "TLS_AES_256_GCM_SHA384", null);
        String output = captureOutput(() -> printer.print(result, "raw jsse content here", List.of(), false));
        assertFalse(output.contains("raw jsse content here"));
    }

    @Test
    void stepsAreNumberedInOutput() {
        HandshakeResult result = HandshakeResult.success("example.com", 443, "TLSv1.3", "TLS_AES_256_GCM_SHA384", null);
        var steps = List.of(
                new HandshakeStep("ClientHello", List.of("Offered protocols : TLSv1.3")),
                new HandshakeStep("ServerHello", List.of("Selected protocol : TLSv1.3"))
        );
        String output = captureOutput(() -> printer.print(result, "", steps, false));
        assertTrue(output.contains("[1] ClientHello"));
        assertTrue(output.contains("[2] ServerHello"));
    }

    @Test
    void expiredCertErrorHasHint() {
        HandshakeResult result = HandshakeResult.failure("example.com", 443,
                new javax.net.ssl.SSLHandshakeException("certificate_expired"));
        String output = captureOutput(() -> printer.print(result, "", List.of(), false));
        assertTrue(output.contains("expired"));
        assertTrue(output.contains("--insecure"));
    }
}
