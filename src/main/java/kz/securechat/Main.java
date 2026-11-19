package kz.securechat;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.CountDownLatch;

public final class Main {
    private Main() { }
    public static void main(String[] args) {
        // Windows console defaults may not contain Kazakh characters. Always emit UTF-8.
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, StandardCharsets.UTF_8));
        try {
            if (args.length == 0) { usage(); return; }
            switch (args[0]) {
                case "server" -> runServer(args);
                case "client" -> runClient(args);
                case "demo" -> Demo.run();
                default -> throw new IllegalArgumentException("Unknown command: " + args[0]);
            }
        } catch (Exception e) {
            System.err.println("Ошибка: " + safe(e.getMessage()));
            System.exit(1);
        }
    }

    private static void runServer(String[] args) throws Exception {
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 5555;
        String bind = args.length > 2 ? args[2] : "127.0.0.1";
        try (ChatServer server = new ChatServer(bind, port)) {
            server.start();
            Path pin = Path.of(".runtime", "server.fingerprint");
            Files.createDirectories(pin.getParent());
            Files.writeString(pin, server.fingerprint() + System.lineSeparator(), StandardCharsets.UTF_8);
            System.out.println("Сервер: " + bind + ":" + server.port());
            System.out.println("SHA-256 fingerprint: " + server.fingerprint());
            System.out.println("Публичный отпечаток сохранён в " + pin);
            System.out.println("Ожидаю клиентов. Для остановки: Ctrl+C.");
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));
            new CountDownLatch(1).await();
        }
    }

    private static void runClient(String[] args) throws Exception {
        if (args.length < 2) throw new IllegalArgumentException("Specify a name, e.g. client Alice");
        String host = args.length > 2 ? args[2] : "127.0.0.1";
        int port = args.length > 3 ? Integer.parseInt(args[3]) : 5555;
        String fingerprint;
        if (args.length > 4) fingerprint = args[4];
        else {
            if (!host.equals("127.0.0.1") && !host.equals("localhost"))
                throw new IllegalArgumentException("For a remote server specify a fingerprint obtained through a trusted channel");
            fingerprint = Files.readString(Path.of(".runtime", "server.fingerprint")).trim();
        }
        try (ChatClient client = ChatClient.connect(host, port, args[1], fingerprint)) {
            System.out.println("Подключён: " + args[1] + ". Отпечаток сервера проверен.");
            System.out.println("Формат: /to Bob Сәлем!  |  /quit - выход");
            Thread receiver = new Thread(() -> {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        ChatMessage message = client.receiveMessage();
                        System.out.println("[" + message.type() + "] " + safe(message.sender()) + ": " + safe(message.text()));
                    }
                } catch (Exception e) { System.out.println("Соединение закрыто. Введите /quit для выхода."); }
            }, "secure-chat-reader");
            receiver.setDaemon(true); receiver.start();
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line;
            while ((line = console.readLine()) != null && !line.equals("/quit")) {
                if (!line.startsWith("/to ")) { System.out.println("Используйте: /to Bob сообщение"); continue; }
                String[] parts = line.split(" ", 3);
                if (parts.length < 3) { System.out.println("Введите имя получателя и сообщение."); continue; }
                try { client.sendMessage(parts[1], parts[2]); }
                catch (IllegalArgumentException e) { System.out.println(e.getMessage()); }
            }
        }
    }

    static String safe(String text) {
        return text == null ? "Unknown error" : text.replaceAll("[\\p{Cc}\\p{Cf}&&[^\\n\\t]]", "?");
    }

    private static void usage() {
        System.out.println("Java Secure Chat | Java 21 | RSA-OAEP + AES-256-GCM");
        System.out.println("  java -jar target/secure-chat.jar demo");
        System.out.println("  java -jar target/secure-chat.jar server [port] [bind-address]");
        System.out.println("  java -jar target/secure-chat.jar client NAME [host] [port] [trusted-fingerprint]");
    }
}
