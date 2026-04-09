package net.cwnk.ssldebugger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

public class SslHandshakeProbe {

    private static final int TIMEOUT_MS = 10_000;

    public HandshakeResult probe(String host, int port, String proxy, boolean insecure) {
        try {
            SSLContext sslContext;
            if (insecure) {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{new TrustAllTrustManager()}, null);
            } else {
                sslContext = SSLContext.getDefault();
            }

            SSLSocket sslSocket;
            if (proxy != null && !proxy.isBlank()) {
                sslSocket = connectViaProxy(host, port, proxy, sslContext);
            } else {
                sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket();
                sslSocket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            }

            sslSocket.setSoTimeout(TIMEOUT_MS);
            sslSocket.startHandshake();

            var session = sslSocket.getSession();
            var certs = (X509Certificate[]) session.getPeerCertificates();
            var result = HandshakeResult.success(host, port, session.getProtocol(), session.getCipherSuite(), certs);
            sslSocket.close();
            return result;

        } catch (Exception e) {
            return HandshakeResult.failure(host, port, e);
        }
    }

    private SSLSocket connectViaProxy(String host, int port, String proxy, SSLContext sslContext) throws Exception {
        String[] parts = proxy.split(":", 2);
        String proxyHost = parts[0];
        int proxyPort = Integer.parseInt(parts[1]);

        Socket tunnel = new Socket();
        tunnel.connect(new InetSocketAddress(proxyHost, proxyPort), TIMEOUT_MS);
        tunnel.setSoTimeout(TIMEOUT_MS);

        PrintWriter out = new PrintWriter(tunnel.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(tunnel.getInputStream()));

        out.printf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port);
        out.flush();

        String responseLine = in.readLine();
        if (responseLine == null || !responseLine.contains("200")) {
            tunnel.close();
            throw new RuntimeException("Proxy CONNECT failed: " + responseLine);
        }
        // Drain headers
        String line;
        while ((line = in.readLine()) != null && !line.isEmpty()) {
            // consume remaining headers
        }

        return (SSLSocket) sslContext.getSocketFactory().createSocket(tunnel, host, port, true);
    }
}
