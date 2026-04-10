package net.cwnk.ssldebugger;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SslDebuggerCliTest {

    @Test
    void unsupportedTlsVersionAbortsWithExitCode2() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        CommandLine cmd = new CommandLine(new SslDebuggerCli());
        cmd.setErr(new PrintWriter(err, true));

        int exitCode = cmd.execute("--host", "example.com", "--tls-version", "TLSv99");

        assertEquals(2, exitCode);
        String errOut = err.toString(StandardCharsets.UTF_8);
        assertTrue(errOut.contains("not supported"), "Expected 'not supported' in: " + errOut);
        assertTrue(errOut.contains("TLSv99"), "Expected version name in: " + errOut);
    }

    @Test
    void unknownCipherSuiteAbortsWithExitCode2() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        CommandLine cmd = new CommandLine(new SslDebuggerCli());
        cmd.setErr(new PrintWriter(err, true));

        int exitCode = cmd.execute("--host", "example.com", "--cipher-suites", "FAKE_CIPHER_SUITE");

        assertEquals(2, exitCode);
        String errOut = err.toString(StandardCharsets.UTF_8);
        assertTrue(errOut.contains("FAKE_CIPHER_SUITE"), "Expected invalid suite name in: " + errOut);
        assertTrue(errOut.contains("not supported"), "Expected 'not supported' in: " + errOut);
    }

    @Test
    void multipleUnknownCipherSuitesAllReportedInError() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        CommandLine cmd = new CommandLine(new SslDebuggerCli());
        cmd.setErr(new PrintWriter(err, true));

        int exitCode = cmd.execute("--host", "example.com", "--cipher-suites", "FAKE_ONE,FAKE_TWO");

        assertEquals(2, exitCode);
        String errOut = err.toString(StandardCharsets.UTF_8);
        assertTrue(errOut.contains("FAKE_ONE"), "Expected FAKE_ONE in: " + errOut);
        assertTrue(errOut.contains("FAKE_TWO"), "Expected FAKE_TWO in: " + errOut);
        assertTrue(errOut.contains("not supported"), "Expected 'not supported' in: " + errOut);
    }

    @Test
    void shorthandTlsVersionIsNormalized() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        CommandLine cmd = new CommandLine(new SslDebuggerCli());
        cmd.setErr(new PrintWriter(err, true));

        // "99" normalizes to "TLSv99" — unsupported, so exits 2, but error must show normalized name
        int exitCode = cmd.execute("--host", "example.com", "--tls-version", "99");

        assertEquals(2, exitCode);
        String errOut = err.toString(StandardCharsets.UTF_8);
        assertTrue(errOut.contains("TLSv99"), "Expected normalized 'TLSv99' in error: " + errOut);
    }
}
