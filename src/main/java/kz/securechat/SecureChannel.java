package kz.securechat;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.GeneralSecurityException;

/** One writer and one reader may operate concurrently on a connection. */
final class SecureChannel {
    record Received(String recipient, byte[] plaintext) { }
    private final DataInputStream in;
    private final DataOutputStream out;
    private final SecretKey key;
    private final boolean client;
    private long sent;
    private long received;

    SecureChannel(DataInputStream in, DataOutputStream out, SecretKey key, boolean client) {
        this.in = in; this.out = out; this.key = key; this.client = client;
    }

    synchronized void send(String recipient, byte[] plaintext) throws IOException, GeneralSecurityException {
        if (sent == Long.MAX_VALUE) throw new IOException("Session exhausted; reconnect");
        // Consume the nonce even if the write fails; callers then close this connection.
        EncryptedMessage message = CryptoService.encryptAES(key, recipient, sent++, client, plaintext);
        Protocol.writeEnvelope(out, message);
    }

    Received receive() throws IOException, GeneralSecurityException {
        EncryptedMessage message = Protocol.readEnvelope(in);
        if (message.sequence() != received || received == Long.MAX_VALUE)
            throw new GeneralSecurityException("Replayed or out-of-order message");
        byte[] plaintext = CryptoService.decryptAES(key, message, !client);
        received++;
        return new Received(message.recipientId(), plaintext);
    }
}
