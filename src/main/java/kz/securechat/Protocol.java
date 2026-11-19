package kz.securechat;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Bounded, length-prefixed protocol. No Java object deserialization. */
final class Protocol {
    static final int MAGIC = 0x53434831;
    static final int MAX_TEXT = 4096;
    static final int MAX_FRAME = 8192;
    private Protocol() { }

    static void validateId(String id) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{1,24}") || id.equalsIgnoreCase("SERVER"))
            throw new IllegalArgumentException("Name: 1-24 Latin letters, digits, _ or -; SERVER is reserved");
    }

    static byte[] textBytes(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (text.isBlank() || bytes.length > MAX_TEXT)
            throw new IllegalArgumentException("Message must contain text and be at most 4096 UTF-8 bytes");
        return bytes;
    }

    static String utf8(byte[] bytes) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) { throw new IOException("Invalid UTF-8", e); }
    }

    static void writeBytes(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length); out.write(value);
    }
    static byte[] readBytes(DataInputStream in, int max) throws IOException {
        int size = in.readInt();
        if (size < 0 || size > max) throw new IOException("Invalid frame length");
        byte[] bytes = new byte[size]; in.readFully(bytes); return bytes;
    }
    static void writeString(DataOutputStream out, String value) throws IOException {
        writeBytes(out, value.getBytes(StandardCharsets.UTF_8));
    }
    static String readString(DataInputStream in, int max) throws IOException { return utf8(readBytes(in, max)); }

    static void writeEnvelope(DataOutputStream out, EncryptedMessage message) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream frame = new DataOutputStream(buffer);
        writeString(frame, message.recipientId()); frame.writeLong(message.sequence());
        writeBytes(frame, message.iv()); writeBytes(frame, message.ciphertext()); writeBytes(frame, message.authTag());
        if (buffer.size() > MAX_FRAME) throw new IOException("Frame too large");
        writeBytes(out, buffer.toByteArray()); out.flush();
    }

    static EncryptedMessage readEnvelope(DataInputStream in) throws IOException {
        DataInputStream frame = new DataInputStream(new ByteArrayInputStream(readBytes(in, MAX_FRAME)));
        String recipient = readString(frame, 24);
        try { validateId(recipient); } catch (IllegalArgumentException e) { throw new IOException(e.getMessage()); }
        EncryptedMessage message = new EncryptedMessage(recipient, frame.readLong(), readBytes(frame, 12),
                readBytes(frame, MAX_FRAME), readBytes(frame, 16));
        if (frame.available() != 0) throw new IOException("Trailing frame data");
        return message;
    }
}
