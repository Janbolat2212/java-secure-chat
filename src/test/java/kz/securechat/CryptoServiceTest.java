package kz.securechat;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {
    static KeyPair rsa;
    SecretKey key;
    @BeforeAll static void keys() throws Exception { rsa = CryptoService.generateRSAKeys(); }
    @BeforeEach void aes() throws Exception { key = CryptoService.generateAESKey(); }
    EncryptedMessage seal(String text) throws Exception {
        return CryptoService.encryptAES(key, "Bob", 0, true, text.getBytes(StandardCharsets.UTF_8));
    }
    @ParameterizedTest @ValueSource(strings = {"Hello", "Сәлем, Қазақстан! Привет! 🔐", ""})
    void restoresExactText(String text) throws Exception {
        assertEquals(text, new String(CryptoService.decryptAES(key, seal(text), true), StandardCharsets.UTF_8));
    }
    @Test void restoresLongMessage() throws Exception {
        String text = "a".repeat(4096);
        assertArrayEquals(text.getBytes(StandardCharsets.UTF_8), CryptoService.decryptAES(key, seal(text), true));
    }
    @Test void rejectsWrongAesKey() throws Exception {
        EncryptedMessage message = seal("secret");
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptAES(CryptoService.generateAESKey(), message, true));
    }
    @Test void rejectsChangedCiphertext() throws Exception {
        EncryptedMessage m = seal("secret"); byte[] changed = m.ciphertext(); changed[0] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptAES(key,
                new EncryptedMessage("Bob", 0, m.iv(), changed, m.authTag()), true));
    }
    @Test void rejectsChangedTag() throws Exception {
        EncryptedMessage m = seal("secret"); byte[] changed = m.authTag(); changed[0] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptAES(key,
                new EncryptedMessage("Bob", 0, m.iv(), m.ciphertext(), changed), true));
    }
    @Test void rejectsChangedRecipient() throws Exception {
        EncryptedMessage m = seal("secret");
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptAES(key,
                new EncryptedMessage("Eve", 0, m.iv(), m.ciphertext(), m.authTag()), true));
    }
    @Test void rejectsChangedIv() throws Exception {
        EncryptedMessage m = seal("secret"); byte[] changed = m.iv(); changed[0] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptAES(key,
                new EncryptedMessage("Bob", 0, changed, m.ciphertext(), m.authTag()), true));
    }
    @Test void rejectsWrongDirection() throws Exception {
        EncryptedMessage m = seal("secret");
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptAES(key, m, false));
    }
    @Test void separatesNonceDirectionsAndSequenceNumbers() {
        assertFalse(Arrays.equals(CryptoService.nonce(true, 0), CryptoService.nonce(false, 0)));
        assertFalse(Arrays.equals(CryptoService.nonce(true, 0), CryptoService.nonce(true, 1)));
    }
    @Test void wrapsAndRestoresAesKeyWithRsaOaep() throws Exception {
        assertArrayEquals(key.getEncoded(), CryptoService.decryptRSA(CryptoService.encryptRSA(key, rsa.getPublic()), rsa.getPrivate()).getEncoded());
    }
    @Test void wrongRsaPrivateKeyCannotUnwrap() throws Exception {
        byte[] wrapped = CryptoService.encryptRSA(key, rsa.getPublic());
        KeyPair other = CryptoService.generateRSAKeys();
        assertThrows(GeneralSecurityException.class, () -> CryptoService.decryptRSA(wrapped, other.getPrivate()));
    }
    @Test void publicKeyEncodingPreservesFingerprint() throws Exception {
        PublicKey decoded = CryptoService.readPublicKey(rsa.getPublic().getEncoded());
        assertEquals(CryptoService.fingerprint(rsa.getPublic()), CryptoService.fingerprint(decoded));
    }
    @Test void acceptsTrustedFingerprint() throws Exception {
        assertDoesNotThrow(() -> CryptoService.verifyFingerprint(rsa.getPublic(), CryptoService.fingerprint(rsa.getPublic())));
    }
    @Test void rejectsWrongFingerprint() {
        assertThrows(GeneralSecurityException.class, () -> CryptoService.verifyFingerprint(rsa.getPublic(), "0".repeat(64)));
    }
    @Test void rejectsMissingFingerprint() {
        assertThrows(GeneralSecurityException.class, () -> CryptoService.verifyFingerprint(rsa.getPublic(), null));
    }
    @Test void envelopeDoesNotExposeMutableArrays() throws Exception {
        EncryptedMessage m = seal("secret"); m.authTag()[0] ^= 1;
        assertEquals("secret", new String(CryptoService.decryptAES(key, m, true), StandardCharsets.UTF_8));
    }
}
