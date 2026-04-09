package net.cwnk.ssldebugger;

import java.util.List;

public record HandshakeStep(String name, List<String> details) {
}
