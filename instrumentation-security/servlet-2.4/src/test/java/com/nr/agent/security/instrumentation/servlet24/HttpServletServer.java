package com.nr.agent.security.instrumentation.servlet24;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.connector.Connector;

import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.junit.rules.ExternalResource;

import javax.servlet.annotation.WebServlet;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;

@WebServlet("/*")
public class HttpServletServer extends ExternalResource {

    private final int port;
    private Tomcat server;
    private File tmp;
    public HttpServletServer() {
        this.port = getRandomPort();
    }

    @Override
    protected void before() throws Throwable {
        startServer();
    }

    @Override
    protected void after() {
        stop();
    }

    private static int getRandomPort() {
        int port = 0;

        try {
            ServerSocket socket = new ServerSocket(0);
            port = socket.getLocalPort();
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port "+ port);
        }
        return port;
    }

    private void startServer () throws Exception {
        TomcatURLStreamHandlerFactory.disable();

        HttpTestServlet servlet = new HttpTestServlet();

        server = new Tomcat();
        server.setPort(port);

        tmp = new File("./tmp");
        String workingDir = tmp.getAbsolutePath();

        server.setBaseDir(workingDir);


        Context context = server.addContext("", tmp.getAbsolutePath());
        Tomcat.addServlet( context, "servlet" , servlet);
        context.addServletMappingDecoded("/*","servlet");

        final Connector connector = new Connector();
        connector.setPort(port);
        server.getService().addConnector(connector);

        server.start();
    }

    public URI getEndPoint(String path) throws URISyntaxException {
        return new URI("http://localhost:" + port + "/" + path);
    }

    private void stop() {
        if (server.getServer() != null && server.getServer().getState() != LifecycleState.DESTROYED) {
            try {
                if (server.getServer().getState() != LifecycleState.STOPPED) {
                    server.stop();
                }

                server.destroy();
            FileUtils.forceDelete(tmp);
            } catch (Exception e) {
                e.printStackTrace();
            }

        }

        tmp = null;
    }
}