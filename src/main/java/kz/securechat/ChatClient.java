package kz.securechat;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;

public final class ChatClient implements AutoCloseable {
    private final Socket socket;
    private final SecureChannel channel;
    private final String clientId;

    private ChatClient(Socket socket, SecureChannel channel, String id) {
        this.socket = socket; this.channel = channel; this.clientId = id;
    }

    public static ChatClient connect(String host, int port, String id, String trustedFingerprint)
            throws IOException, GeneralSecurityException {
        Protocol.validateId(id);
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), 5_000);
            socket.setSoTimeout(15_000); socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            if (in.readInt() != Protocol.MAGIC) throw new IOException("Unsupported server protocol");
            PublicKey serverKey = CryptoService.readPublicKey(Protocol.readBytes(in, 1024));
            CryptoService.verifyFingerprint(serverKey, trustedFingerprint);
            SecretKey aesKey = CryptoService.generateAESKey();
            out.writeInt(Protocol.MAGIC); Protocol.writeString(out, id);
            Protocol.writeBytes(out, CryptoService.encryptRSA(aesKey, serverKey)); out.flush();
            ChatClient client = new ChatClient(socket, new SecureChannel(in, out, aesKey, true), id);
            ChatMessage welcome = client.receiveMessage();
            if (welcome.type() != ChatMessage.Type.WELCOME) throw new IOException(welcome.text());
            socket.setSoTimeout(0);
            return client;
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            try { socket.close(); } catch (IOException ignored) { }
            throw e;
        }
    }

    public void sendMessage(String recipient, String text) throws IOException, GeneralSecurityException {
        Protocol.validateId(recipient);
        byte[] bytes = Protocol.textBytes(text);
        try { channel.send(recipient, bytes); }
        catch (IOException | GeneralSecurityException e) { close(); throw e; }
    }

    public ChatMessage receiveMessage() throws IOException, GeneralSecurityException {
        try {
            SecureChannel.Received packet = channel.receive();
            if (!packet.recipient().equals(clientId)) throw new GeneralSecurityException("Wrong recipient");
            return ChatMessage.decode(packet.plaintext());
        } catch (IOException | GeneralSecurityException e) { close(); throw e; }
    }

    void setReadTimeout(int millis) throws SocketException { socket.setSoTimeout(millis); }
    @Override public void close() throws IOException { socket.close(); }
}
