package net.cwnk.ssldebugger;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HandshakeStepParserTest {

    private final HandshakeStepParser parser = new HandshakeStepParser();

    @Test
    void emptyInputReturnsNoSteps() {
        assertEquals(List.of(), parser.parse(""));
        assertEquals(List.of(), parser.parse(null));
    }

    @Test
    void parsesClientHello() {
        String jsse = """
                *** ClientHello, TLSv1.3
                Versions: [TLSv1.3, TLSv1.2]
                Cipher Suites: [TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
                Extensions: [server_name, supported_groups]
                *** ServerHello, TLSv1.3
                """;
        List<HandshakeStep> steps = parser.parse(jsse);
        assertTrue(steps.stream().anyMatch(s -> s.name().equals("ClientHello")));
    }

    @Test
    void parsesServerHello() {
        String jsse = """
                *** ClientHello, TLSv1.3
                *** ServerHello, TLSv1.3
                CipherSuite: TLS_AES_256_GCM_SHA384
                """;
        List<HandshakeStep> steps = parser.parse(jsse);
        assertTrue(steps.stream().anyMatch(s -> s.name().equals("ServerHello")));
        HandshakeStep serverHello = steps.stream().filter(s -> s.name().equals("ServerHello")).findFirst().orElseThrow();
        assertTrue(serverHello.details().stream().anyMatch(d -> d.contains("TLSv1.3")));
    }

    @Test
    void parsesFinished() {
        String jsse = """
                *** Finished
                verify_data: [...]
                """;
        List<HandshakeStep> steps = parser.parse(jsse);
        assertTrue(steps.stream().anyMatch(s -> s.name().equals("Finished")));
    }

    @Test
    void degradesGracefullyOnUnrecognizedOutput() {
        String jsse = "some random text that does not look like JSSE output at all";
        List<HandshakeStep> steps = parser.parse(jsse);
        // Should return empty list, not throw
        assertNotNull(steps);
    }
}
