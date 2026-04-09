package net.cwnk.ssldebugger;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@Command(
        name = "ssl-debugger",
        mixinStandardHelpOptions = true,
        version = "1.0",
        description = "Diagnoses SSL/TLS handshake failures by showing the full handshake trace and a human-readable summary."
)
public class SslDebuggerCli implements Callable<Integer> {

    @Option(names = {"--host"}, required = true, description = "Target hostname")
    private String host;

    @Option(names = {"--port"}, required = true, description = "Target port")
    private int port;

    @Option(names = {"--proxy"}, description = "HTTP proxy as host:port")
    private String proxy;

    @Option(names = {"--insecure"}, description = "Skip certificate validation")
    private boolean insecure;

    @Option(names = {"--raw"}, description = "Also print the full raw JSSE debug output")
    private boolean raw;

    private final JsseOutputCapture capture = new JsseOutputCapture();
    private final SslHandshakeProbe probe = new SslHandshakeProbe();
    private final HandshakeStepParser parser = new HandshakeStepParser();
    private final ResultPrinter printer = new ResultPrinter();

    @Override
    public Integer call() {
        capture.start();
        HandshakeResult result = probe.probe(host, port, proxy, insecure);
        String rawOutput = capture.stop();

        var steps = parser.parse(rawOutput);
        printer.print(result, rawOutput, steps, raw);

        return result.success() ? 0 : 1;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new SslDebuggerCli()).execute(args));
    }
}
