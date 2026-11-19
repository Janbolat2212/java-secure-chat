package kz.securechat;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** Uses standard JCA only. Keys remain in memory for the lifetime of a session. */
public final class CryptoService {
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private CryptoService() { }

    public static SecretKey generateAESKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    public static KeyPair generateRSAKeys() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static PublicKey readPublicKey(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static byte[] encryptRSA(SecretKey key, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP);
        return cipher.doFinal(key.getEncoded());
    }

    public static SecretKey decryptRSA(byte[] wrapped, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP);
        byte[] raw = cipher.doFinal(wrapped);
        try {
            if (raw.length != 32) throw new GeneralSecurityException("Expected an AES-256 key");
            return new SecretKeySpec(raw, "AES");
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    public static String fingerprint(PublicKey key) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getEncoded()));
    }

    public static void verifyFingerprint(PublicKey key, String expected) throws GeneralSecurityException {
        if (expected == null || !expected.matches("(?i)[0-9a-f]{64}"))
            throw new GeneralSecurityException("A trusted SHA-256 fingerprint is required");
        if (!MessageDigest.isEqual(HexFormat.of().parseHex(fingerprint(key)), HexFormat.of().parseHex(expected)))
            throw new GeneralSecurityException("Server fingerprint mismatch; connection refused");
    }

    // Each session has a fresh AES key. Direction prefixes keep both counters disjoint.
    public static byte[] nonce(boolean fromClient, long sequence) {
        if (sequence < 0) throw new IllegalArgumentException("Negative sequence");
        return ByteBuffer.allocate(12).putInt(fromClient ? 0x434c4e54 : 0x53525652).putLong(sequence).array();
    }

    private static byte[] aad(String recipient, long sequence, boolean fromClient) {
        return ("SCH1|" + (fromClient ? "C" : "S") + "|" + sequence + "|" + recipient)
                .getBytes(StandardCharsets.UTF_8);
    }

    public static EncryptedMessage encryptAES(SecretKey key, String recipient, long sequence,
                                               boolean fromClient, byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = nonce(fromClient, sequence);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad(recipient, sequence, fromClient));
        byte[] sealed = cipher.doFinal(plaintext);
        return new EncryptedMessage(recipient, sequence, iv,
                Arrays.copyOf(sealed, sealed.length - 16), Arrays.copyOfRange(sealed, sealed.length - 16, sealed.length));
    }

    public static byte[] decryptAES(SecretKey key, EncryptedMessage message, boolean fromClient)
            throws GeneralSecurityException {
        if (message.sequence() < 0 || message.iv().length != 12 || message.authTag().length != 16)
            throw new GeneralSecurityException("Invalid encrypted envelope");
        if (!MessageDigest.isEqual(message.iv(), nonce(fromClient, message.sequence())))
            throw new GeneralSecurityException("Unexpected nonce");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, message.iv()));
        cipher.updateAAD(aad(message.recipientId(), message.sequence(), fromClient));
        return cipher.doFinal(ByteBuffer.allocate(message.ciphertext().length + 16)
                .put(message.ciphertext()).put(message.authTag()).array());
    }
}
