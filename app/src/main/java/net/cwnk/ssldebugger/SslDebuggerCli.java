package net.cwnk.ssldebugger;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Callable;

@Command(
        name = "ssl-debugger",
        mixinStandardHelpOptions = true,
        version = "0.2",
        description = "Diagnoses SSL/TLS handshake failures by showing the full handshake trace and a human-readable summary."
)
public class SslDebuggerCli implements Callable<Integer> {

    private static final String OUTPUT_DEFAULT_SENTINEL = "__default__";
    private static final DateTimeFormatter TIMESTAMP_FMT = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss");

    @Option(names = {"--host"}, required = true, description = "Target hostname")
    private String host;

    @Option(names = {"--port"}, description = "Target port (default: 443)")
    private int port = 443;

    @Option(names = {"--proxy"}, description = "HTTP proxy as host:port")
    private String proxy;

    @Option(names = {"--insecure"}, description = "Skip certificate validation")
    private boolean insecure;

    @Option(names = {"--raw"}, description = "Also print the full raw JSSE debug output")
    private boolean raw;

    @Option(
            names = {"--output"},
            arity = "0..1",
            fallbackValue = OUTPUT_DEFAULT_SENTINEL,
            paramLabel = "<file>",
            description = "Write output to a file in addition to stdout. If no filename is given, a default name is used: ssl-debug-<host>-<timestamp>.txt"
    )
    private String outputPath;

    private final JsseOutputCapture capture = new JsseOutputCapture();
    private final SslHandshakeProbe probe = new SslHandshakeProbe();
    private final HandshakeStepParser parser = new HandshakeStepParser();
    private final ResultPrinter printer = new ResultPrinter();

    @Override
    public Integer call() {
        Path resolvedOutput = resolveOutputPath();

        if (resolvedOutput != null) {
            try {
                resolvedOutput.toFile().getParentFile();
                // Validate path is writable before running the probe
                resolvedOutput.toFile().createNewFile();
            } catch (IOException e) {
                System.err.println("Error: cannot open output file: " + resolvedOutput + " (" + e.getMessage() + ")");
                return 2;
            }
        }

        capture.start();
        HandshakeResult result = probe.probe(host, port, proxy, insecure);
        String rawOutput = capture.stop();

        var steps = parser.parse(rawOutput);

        if (resolvedOutput != null) {
            try (FileOutputStream fos = new FileOutputStream(resolvedOutput.toFile());
                 PrintStream teeOut = new PrintStream(new TeeOutputStream(System.out, fos))) {
                printer.print(result, rawOutput, steps, raw, teeOut);
            } catch (IOException e) {
                System.err.println("Error: failed to write output file: " + e.getMessage());
                return 2;
            }
            System.err.println("Output written to: " + resolvedOutput);
        } else {
            printer.print(result, rawOutput, steps, raw, System.out);
        }

        return result.success() ? 0 : 1;
    }

    private Path resolveOutputPath() {
        if (outputPath == null) {
            return null;
        }
        if (OUTPUT_DEFAULT_SENTINEL.equals(outputPath)) {
            String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);
            return Path.of("ssl-debug-" + host + "-" + timestamp + ".txt");
        }
        return Path.of(outputPath);
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new SslDebuggerCli()).execute(args));
    }
}
