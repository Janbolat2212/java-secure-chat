package kz.securechat;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;

/** A server-owned connection and its independent AES key/counters. */
final class ClientSession implements AutoCloseable {
    private final String clientId;
    private final Socket socket;
    private final SecureChannel channel;

    ClientSession(String clientId, Socket socket, SecureChannel channel) {
        this.clientId = clientId; this.socket = socket; this.channel = channel;
    }
    String clientId() { return clientId; }
    synchronized void send(ChatMessage message) throws IOException, GeneralSecurityException {
        channel.send(clientId, message.encode());
    }
    SecureChannel.Received receive() throws IOException, GeneralSecurityException { return channel.receive(); }
    @Override public void close() throws IOException { socket.close(); }
}
