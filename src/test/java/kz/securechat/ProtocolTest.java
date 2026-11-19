package kz.securechat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

class ProtocolTest {
    @ParameterizedTest @ValueSource(ints = {-1, 8193, Integer.MAX_VALUE})
    void refusesUnboundedAllocation(int length) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        new DataOutputStream(bytes).writeInt(length);
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()));
        assertThrows(IOException.class, () -> Protocol.readBytes(input, Protocol.MAX_FRAME));
    }
    @Test void rejectsTruncatedFrame() {
        byte[] bytes = {0, 0, 0, 4, 1};
        assertThrows(EOFException.class, () -> Protocol.readBytes(new DataInputStream(new ByteArrayInputStream(bytes)), 100));
    }
    @Test void rejectsMalformedUtf8() { assertThrows(IOException.class, () -> Protocol.utf8(new byte[]{(byte) 0xc0, (byte) 0xaf})); }
    @ParameterizedTest @ValueSource(strings = {"", " ", "SERVER", "user/name", "veryveryveryveryverylongname"})
    void rejectsInvalidNames(String name) { assertThrows(IllegalArgumentException.class, () -> Protocol.validateId(name)); }
    @Test void rejectsBlankChatText() { assertThrows(IllegalArgumentException.class, () -> Protocol.textBytes(" \n")); }
    @Test void limitsUtf8BytesNotOnlyCharacters() { assertThrows(IllegalArgumentException.class, () -> Protocol.textBytes("ә".repeat(2049))); }
    @Test void serializesEncryptedEnvelope() throws Exception {
        EncryptedMessage message = CryptoService.encryptAES(CryptoService.generateAESKey(), "Bob", 3, true, new byte[]{1, 2, 3});
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        Protocol.writeEnvelope(new DataOutputStream(bytes), message);
        EncryptedMessage restored = Protocol.readEnvelope(new DataInputStream(new ByteArrayInputStream(bytes.toByteArray())));
        assertEquals("Bob", restored.recipientId()); assertEquals(3, restored.sequence());
        assertArrayEquals(message.ciphertext(), restored.ciphertext());
        assertArrayEquals(message.iv(), restored.iv()); assertArrayEquals(message.authTag(), restored.authTag());
    }
    @Test void stripsTerminalEscapeSequences() { assertFalse(Main.safe("hello\u001b[31m").contains("\u001b")); }
}
