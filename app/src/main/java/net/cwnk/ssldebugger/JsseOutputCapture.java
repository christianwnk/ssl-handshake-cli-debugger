package net.cwnk.ssldebugger;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

public class JsseOutputCapture {

    private PrintStream originalErr;
    private ByteArrayOutputStream buffer;

    public void start() {
        originalErr = System.err;
        buffer = new ByteArrayOutputStream();
        System.setErr(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        System.setProperty("javax.net.debug", "ssl:all");
    }

    public String stop() {
        System.err.flush();
        System.setErr(originalErr);
        System.clearProperty("javax.net.debug");
        return buffer.toString(StandardCharsets.UTF_8);
    }
}
