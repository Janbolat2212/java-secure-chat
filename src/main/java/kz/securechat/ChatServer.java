package kz.securechat;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Trusted relay: decrypts each message and encrypts it for the receiving session. */
public final class ChatServer implements AutoCloseable {
    private final KeyPair rsaKeyPair = CryptoService.generateRSAKeys();
    private final ServerSocket serverSocket = new ServerSocket();
    private final ConcurrentMap<String, ClientSession> sessions = new ConcurrentHashMap<>();
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final ExecutorService workers = Executors.newFixedThreadPool(32);
    private final Semaphore capacity = new Semaphore(32);
    private final AtomicBoolean running = new AtomicBoolean();
    private final String host;
    private final int requestedPort;
    private Thread acceptThread;

    public ChatServer(String host, int port) throws IOException, GeneralSecurityException {
        this.host = host; this.requestedPort = port;
    }

    public void start() throws IOException {
        if (!running.compareAndSet(false, true)) throw new IllegalStateException("Already started");
        try { serverSocket.bind(new InetSocketAddress(host, requestedPort)); }
        catch (IOException e) { running.set(false); close(); throw e; }
        acceptThread = new Thread(this::acceptClients, "secure-chat-accept");
        acceptThread.start();
    }

    public int port() { return serverSocket.getLocalPort(); }
    public String fingerprint() throws GeneralSecurityException { return CryptoService.fingerprint(rsaKeyPair.getPublic()); }

    private void acceptClients() {
        while (running.get()) {
            Socket socket = null;
            try {
                socket = serverSocket.accept();
                if (!running.get()) { socket.close(); break; }
                if (!capacity.tryAcquire()) { socket.close(); continue; }
                sockets.add(socket);
                Socket accepted = socket;
                try { workers.execute(() -> handle(accepted)); }
                catch (RejectedExecutionException e) {
                    sockets.remove(socket); capacity.release(); socket.close();
                }
            } catch (IOException e) {
                if (running.get()) System.err.println("Server connection error: " + e.getClass().getSimpleName());
            }
        }
    }

    private void handle(Socket socket) {
        ClientSession session = null;
        try (socket) {
            socket.setSoTimeout(15_000);
            socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeInt(Protocol.MAGIC);
            Protocol.writeBytes(out, rsaKeyPair.getPublic().getEncoded()); out.flush();
            if (in.readInt() != Protocol.MAGIC) throw new IOException("Unsupported protocol");
            String id = Protocol.readString(in, 24); Protocol.validateId(id);
            SecretKey aesKey = CryptoService.decryptRSA(Protocol.readBytes(in, 256), rsaKeyPair.getPrivate());
            session = new ClientSession(id, socket, new SecureChannel(in, out, aesKey, false));
            // Hold the session lock until WELCOME is sent, even if another user routes a message now.
            synchronized (session) {
                if (sessions.putIfAbsent(id, session) != null) {
                    session.send(new ChatMessage(ChatMessage.Type.ERROR, "SERVER", "Name already connected"));
                    return;
                }
                session.send(new ChatMessage(ChatMessage.Type.WELCOME, "SERVER", "Connected as " + id));
            }
            socket.setSoTimeout(0);
            while (running.get()) {
                SecureChannel.Received packet = session.receive();
                String text = Protocol.utf8(packet.plaintext()); Protocol.textBytes(text);
                forwardMessage(session, packet.recipient(), text);
            }
        } catch (EOFException | SocketException e) {
            // Normal disconnect; do not print keys or message contents.
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            System.err.println("Connection rejected/closed: " + e.getClass().getSimpleName());
        } finally {
            if (session != null) sessions.remove(session.clientId(), session);
            sockets.remove(socket); capacity.release();
        }
    }

    private void forwardMessage(ClientSession sender, String recipient, String text)
            throws IOException, GeneralSecurityException {
        ClientSession receiver = sessions.get(recipient);
        if (receiver == null) {
            sender.send(new ChatMessage(ChatMessage.Type.ERROR, "SERVER", "Recipient is not connected: " + recipient));
            return;
        }
        try {
            receiver.send(new ChatMessage(ChatMessage.Type.CHAT, sender.clientId(), text));
        } catch (IOException | GeneralSecurityException e) {
            sessions.remove(recipient, receiver);
            try { receiver.close(); } catch (IOException ignored) { }
            sender.send(new ChatMessage(ChatMessage.Type.ERROR, "SERVER", "Recipient disconnected: " + recipient));
        }
    }

    @Override public void close() {
        running.set(false);
        try { serverSocket.close(); } catch (IOException ignored) { }
        sockets.forEach(socket -> { try { socket.close(); } catch (IOException ignored) { } });
        workers.shutdownNow();
        try {
            if (acceptThread != null) acceptThread.join(3_000);
            workers.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        sessions.clear();
    }
}
