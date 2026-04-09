package net.cwnk.ssldebugger;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class TeeOutputStreamTest {

    @Test
    void writesToBothStreams() throws IOException {
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try (TeeOutputStream tee = new TeeOutputStream(a, b)) {
            tee.write("hello".getBytes(StandardCharsets.UTF_8));
        }
        assertEquals("hello", a.toString(StandardCharsets.UTF_8));
        assertEquals("hello", b.toString(StandardCharsets.UTF_8));
    }

    @Test
    void flushesAndClosesGracefully() throws IOException {
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        TeeOutputStream tee = new TeeOutputStream(a, b);
        tee.write(42);
        tee.flush();
        tee.close();
        assertEquals(1, a.toByteArray().length);
        assertEquals(1, b.toByteArray().length);
    }

    @Test
    void printStreamWrappedTeeWritesToBothStreams() {
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(new TeeOutputStream(a, b), true, StandardCharsets.UTF_8)) {
            ps.println("tee output");
        }
        assertTrue(a.toString(StandardCharsets.UTF_8).contains("tee output"));
        assertTrue(b.toString(StandardCharsets.UTF_8).contains("tee output"));
    }
}
