package net.cwnk.ssldebugger;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Wraps a delegate TrustManager and captures the server certificate chain
 * before delegating validation. This allows us to display the chain even
 * when validation fails (e.g. expired cert, unknown CA).
 */
public class CapturingTrustManager implements X509TrustManager {

    private final X509TrustManager delegate;
    private X509Certificate[] capturedChain;

    public CapturingTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.capturedChain = chain;
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    public X509Certificate[] getCapturedChain() {
        return capturedChain;
    }
}
