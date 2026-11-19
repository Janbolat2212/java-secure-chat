package kz.securechat;

import org.junit.jupiter.api.*;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class ChatIntegrationTest {
    ChatServer server;
    final List<ChatClient> clients = new ArrayList<>();
    @BeforeEach void start() throws Exception { server = new ChatServer("127.0.0.1", 0); server.start(); }
    @AfterEach void stop() throws Exception {
        for (ChatClient client : clients) client.close();
        server.close();
    }
    ChatClient client(String id) throws Exception {
        ChatClient client = ChatClient.connect("127.0.0.1", server.port(), id, server.fingerprint());
        client.setReadTimeout(3_000); clients.add(client); return client;
    }
    @Test void exchangesMessagesInBothDirections() throws Exception {
        ChatClient alice = client("Alice"), bob = client("Bob");
        alice.sendMessage("Bob", "Сәлем! 🔐");
        assertEquals(new ChatMessage(ChatMessage.Type.CHAT, "Alice", "Сәлем! 🔐"), bob.receiveMessage());
        bob.sendMessage("Alice", "Привет!"); assertEquals("Привет!", alice.receiveMessage().text());
    }
    @Test void preservesMessageOrder() throws Exception {
        ChatClient alice = client("Alice"), bob = client("Bob");
        for (int i = 0; i < 20; i++) alice.sendMessage("Bob", "message-" + i);
        for (int i = 0; i < 20; i++) assertEquals("message-" + i, bob.receiveMessage().text());
    }
    @Test void supportsSimultaneousSenders() throws Exception {
        ChatClient alice = client("Alice"), bob = client("Bob"), carol = client("Carol");
        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            Future<?> a = pool.submit(() -> { try { alice.sendMessage("Bob", "A"); } catch (Exception e) { throw new RuntimeException(e); } });
            Future<?> c = pool.submit(() -> { try { carol.sendMessage("Bob", "C"); } catch (Exception e) { throw new RuntimeException(e); } });
            a.get(3, TimeUnit.SECONDS); c.get(3, TimeUnit.SECONDS);
            assertEquals(java.util.Set.of("Alice", "Carol"), java.util.Set.of(bob.receiveMessage().sender(), bob.receiveMessage().sender()));
        }
    }
    @Test void returnsEncryptedErrorForOfflineRecipient() throws Exception {
        ChatClient alice = client("Alice"); alice.sendMessage("Nobody", "hello");
        ChatMessage error = alice.receiveMessage();
        assertEquals(ChatMessage.Type.ERROR, error.type()); assertTrue(error.text().contains("Nobody"));
    }
    @Test void rejectsDuplicateNameWithoutEvictingOriginal() throws Exception {
        ChatClient alice = client("Alice");
        assertThrows(IOException.class, () -> ChatClient.connect("127.0.0.1", server.port(), "Alice", server.fingerprint()));
        ChatClient bob = client("Bob"); bob.sendMessage("Alice", "still here");
        assertEquals("still here", alice.receiveMessage().text());
    }
    @Test void rejectsUntrustedServerKey() {
        assertThrows(GeneralSecurityException.class, () -> ChatClient.connect("127.0.0.1", server.port(), "Alice", "0".repeat(64)));
    }
    @Test void invalidUserInputDoesNotBreakSession() throws Exception {
        ChatClient alice = client("Alice"), bob = client("Bob");
        assertThrows(IllegalArgumentException.class, () -> alice.sendMessage("Bob", " "));
        assertThrows(IllegalArgumentException.class, () -> alice.sendMessage("Bob", "x".repeat(4097)));
        alice.sendMessage("Bob", "valid"); assertEquals("valid", bob.receiveMessage().text());
    }
    @Test void serverShutdownClosesClients() throws Exception {
        ChatClient alice = client("Alice"); server.close();
        assertThrows(IOException.class, alice::receiveMessage);
    }
    @Test void tamperedNetworkPacketIsRejectedAndNotForwarded() throws Exception {
        ChatClient bob = client("Bob");
        try (RawPeer peer = new RawPeer("Alice")) {
            EncryptedMessage m = peer.encrypt(0); byte[] changed = m.authTag(); changed[0] ^= 1;
            peer.send(new EncryptedMessage("Bob", 0, m.iv(), m.ciphertext(), changed));
            assertEquals(-1, peer.in.read());
            bob.setReadTimeout(200);
            assertThrows(SocketTimeoutException.class, bob::receiveMessage);
        }
    }
    @Test void replayedNetworkPacketIsRejected() throws Exception {
        ChatClient bob = client("Bob");
        try (RawPeer peer = new RawPeer("Alice")) {
            EncryptedMessage m = peer.encrypt(0); peer.send(m);
            assertEquals("hello", bob.receiveMessage().text());
            peer.send(m); assertEquals(-1, peer.in.read());
            bob.setReadTimeout(200); assertThrows(SocketTimeoutException.class, bob::receiveMessage);
        }
    }
    @Test void outOfOrderNetworkPacketIsRejected() throws Exception {
        try (RawPeer peer = new RawPeer("Alice")) { peer.send(peer.encrypt(1)); assertEquals(-1, peer.in.read()); }
    }
    @Test void oversizedNetworkFrameClosesConnection() throws Exception {
        try (RawPeer peer = new RawPeer("Alice")) { peer.out.writeInt(Integer.MAX_VALUE); peer.out.flush(); assertEquals(-1, peer.in.read()); }
    }

    /** Controlled protocol peer for adversarial loopback tests, never an external target. */
    final class RawPeer implements AutoCloseable {
        final Socket socket;
        final DataInputStream in;
        final DataOutputStream out;
        final SecretKey key = CryptoService.generateAESKey();
        RawPeer(String id) throws Exception {
            socket = new Socket("127.0.0.1", server.port()); socket.setSoTimeout(3_000);
            in = new DataInputStream(socket.getInputStream()); out = new DataOutputStream(socket.getOutputStream());
            assertEquals(Protocol.MAGIC, in.readInt());
            PublicKey publicKey = CryptoService.readPublicKey(Protocol.readBytes(in, 1024));
            CryptoService.verifyFingerprint(publicKey, server.fingerprint());
            out.writeInt(Protocol.MAGIC); Protocol.writeString(out, id);
            Protocol.writeBytes(out, CryptoService.encryptRSA(key, publicKey)); out.flush();
            EncryptedMessage welcome = Protocol.readEnvelope(in);
            assertEquals(ChatMessage.Type.WELCOME, ChatMessage.decode(CryptoService.decryptAES(key, welcome, false)).type());
        }
        EncryptedMessage encrypt(long sequence) throws Exception {
            return CryptoService.encryptAES(key, "Bob", sequence, true, "hello".getBytes(StandardCharsets.UTF_8));
        }
        void send(EncryptedMessage message) throws IOException { Protocol.writeEnvelope(out, message); }
        @Override public void close() throws IOException { socket.close(); }
    }
}
