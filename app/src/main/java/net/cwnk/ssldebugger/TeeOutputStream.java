package net.cwnk.ssldebugger;

import java.io.IOException;
import java.io.OutputStream;

class TeeOutputStream extends OutputStream {

    private final OutputStream a;
    private final OutputStream b;

    TeeOutputStream(OutputStream a, OutputStream b) {
        this.a = a;
        this.b = b;
    }

    @Override
    public void write(int c) throws IOException {
        a.write(c);
        b.write(c);
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        a.write(buf, off, len);
        b.write(buf, off, len);
    }

    @Override
    public void flush() throws IOException {
        a.flush();
        b.flush();
    }

    @Override
    public void close() throws IOException {
        try {
            a.close();
        } finally {
            b.close();
        }
    }
}
