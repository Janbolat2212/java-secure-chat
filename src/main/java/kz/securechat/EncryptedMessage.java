package kz.securechat;

/** Wire envelope. Routing and sequence fields are authenticated as GCM AAD. */
public record EncryptedMessage(String recipientId, long sequence, byte[] iv,
                               byte[] ciphertext, byte[] authTag) {
    public EncryptedMessage {
        iv = iv.clone();
        ciphertext = ciphertext.clone();
        authTag = authTag.clone();
    }
    @Override public byte[] iv() { return iv.clone(); }
    @Override public byte[] ciphertext() { return ciphertext.clone(); }
    @Override public byte[] authTag() { return authTag.clone(); }
}
