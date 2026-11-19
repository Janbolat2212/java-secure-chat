package kz.securechat;

import java.io.*;

public record ChatMessage(Type type, String sender, String text) {
    public enum Type { WELCOME, CHAT, ERROR }

    byte[] encode() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeByte(type.ordinal());
        Protocol.writeString(out, sender); Protocol.writeString(out, text);
        return bytes.toByteArray();
    }

    static ChatMessage decode(byte[] bytes) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        int type = in.readUnsignedByte();
        if (type >= Type.values().length) throw new IOException("Unknown message type");
        ChatMessage message = new ChatMessage(Type.values()[type], Protocol.readString(in, 24),
                Protocol.readString(in, Protocol.MAX_TEXT));
        if (in.available() != 0) throw new IOException("Trailing message data");
        return message;
    }
}
