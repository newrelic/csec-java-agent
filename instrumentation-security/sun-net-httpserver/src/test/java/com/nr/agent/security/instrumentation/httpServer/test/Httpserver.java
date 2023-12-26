package com.nr.agent.security.instrumentation.httpServer.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;

public class Httpserver extends ExternalResource {
    private HttpServer server;
    private static final int PORT = getRandomPort();
    @Override
    protected void before() throws Throwable {
        startServer();
    }

    @Override
    protected void after() {
        stop();
    }

    public void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT), 0);
        server.createContext("/", new Handler());
        server.setExecutor(null);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    private static int getRandomPort() {
        int port = 0;
        try (ServerSocket socket = new ServerSocket(0)){
            port = socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port "+ port);
        }
        return port;
    }

    public URI getEndPoint() throws URISyntaxException {
        return new URI("http://localhost:" + PORT);
    }
    static class Handler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            OutputStream os = exchange.getResponseBody();
            String response;
            if(exchange.getRequestMethod().equals("POST")){
                response = String.valueOf(exchange.getRequestBody().hashCode());
            } else {
                response = "Hello, World!\n";
            }
            exchange.sendResponseHeaders(200, response.length());
            os.write(response.getBytes());
            os.flush();
            os.close();
        }
    }
}
