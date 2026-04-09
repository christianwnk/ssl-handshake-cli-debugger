package net.cwnk.ssldebugger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TrustAllTrustManagerTest {

    private final TrustAllTrustManager tm = new TrustAllTrustManager();

    @Test
    void checkClientTrustedDoesNotThrow() {
        assertDoesNotThrow(() -> tm.checkClientTrusted(null, "RSA"));
    }

    @Test
    void checkServerTrustedDoesNotThrow() {
        assertDoesNotThrow(() -> tm.checkServerTrusted(null, "RSA"));
    }

    @Test
    void getAcceptedIssuersReturnsEmptyArray() {
        assertNotNull(tm.getAcceptedIssuers());
        assertEquals(0, tm.getAcceptedIssuers().length);
    }
}
