package net.cwnk.ssldebugger;

import java.security.cert.X509Certificate;

public record HandshakeResult(
        String host,
        int port,
        boolean success,
        String protocol,
        String cipherSuite,
        X509Certificate[] peerCertificates,
        Exception exception
) {
    public static HandshakeResult success(String host, int port, String protocol, String cipherSuite,
                                          X509Certificate[] peerCertificates) {
        return new HandshakeResult(host, port, true, protocol, cipherSuite, peerCertificates, null);
    }

    public static HandshakeResult failure(String host, int port, Exception exception) {
        return new HandshakeResult(host, port, false, null, null, null, exception);
    }
}
