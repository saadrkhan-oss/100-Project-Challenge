import java.io.*;
import java.net.InetSocketAddress;
import com.sun.net.httpserver.*;

public class VulnerableApp {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(9090), 0);
        server.createContext("/deserialize", (exchange) -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String response;
            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(body);
                ObjectInputStream ois = new ObjectInputStream(bais);
                Object obj = ois.readObject();
                ois.close();
                response = "Deserialized OK: " + obj.getClass().getName();
            } catch (Exception e) {
                response = "Error: " + e.getClass().getName() + ": " + e.getMessage();
            }
            byte[] out = response.getBytes();
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.getResponseBody().close();
        });
        server.setExecutor(null);
        server.start();
        System.out.println("[*] Vulnerable Java app on http://127.0.0.1:9090/deserialize");
    }
}
