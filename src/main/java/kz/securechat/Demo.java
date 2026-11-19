package kz.securechat;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/** Reproducible demonstration using real loopback TCP connections. */
final class Demo {
    private Demo() { }
    static void run() throws Exception {
        System.out.println("=== JAVA SECURE CHAT / DEMO ===");
        try (ChatServer server = new ChatServer("127.0.0.1", 0)) {
            server.start();
            System.out.println("[OK] Сервер запущен на 127.0.0.1:" + server.port());
            try (ChatClient alice = ChatClient.connect("127.0.0.1", server.port(), "Alice", server.fingerprint());
                 ChatClient bob = ChatClient.connect("127.0.0.1", server.port(), "Bob", server.fingerprint())) {
                alice.setReadTimeout(5_000); bob.setReadTimeout(5_000);
                System.out.println("[OK] Alice и Bob проверили fingerprint и передали AES-ключи через RSA-OAEP.");
                alice.sendMessage("Bob", "Сәлем, Bob! Қауіпсіз байланыс жұмыс істейді.");
                ChatMessage received = bob.receiveMessage();
                System.out.println("Bob получил от " + received.sender() + ": " + received.text());
                bob.sendMessage("Alice", "Привет, Alice! Сообщение получено.");
                received = alice.receiveMessage();
                System.out.println("Alice получила от " + received.sender() + ": " + received.text());
                alice.sendMessage("OfflineUser", "Проверка ошибки");
                System.out.println("[OK] Нет получателя: " + alice.receiveMessage().text());
            }
            try (ChatClient ignored = ChatClient.connect("127.0.0.1", server.port(), "Mallory", "0".repeat(64))) {
                throw new IllegalStateException("Wrong fingerprint was accepted");
            } catch (GeneralSecurityException expected) {
                System.out.println("[OK] Неверный fingerprint: подключение отклонено.");
            }
        }
        SecretKey key = CryptoService.generateAESKey();
        EncryptedMessage envelope = CryptoService.encryptAES(key, "Bob", 0, true, "Secret demo".getBytes(StandardCharsets.UTF_8));
        System.out.println("Пример шифротекста (hex): " + HexFormat.of().formatHex(envelope.ciphertext()));
        byte[] changed = envelope.ciphertext(); changed[0] ^= 1;
        EncryptedMessage tampered = new EncryptedMessage("Bob", 0, envelope.iv(), changed, envelope.authTag());
        try {
            CryptoService.decryptAES(key, tampered, true);
            throw new IllegalStateException("Tampered message was accepted");
        } catch (GeneralSecurityException expected) {
            System.out.println("[OK] Изменённое сообщение отклонено AES-GCM.");
        }
        System.out.println("=== DEMO PASSED ===");
    }
}
