package com.nr.agent.security.instrumentation.servlet6;

import jakarta.faces.webapp.FacesServlet;
import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.connector.Connector;

import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.junit.rules.ExternalResource;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Set;

@WebServlet("/*")
public class HttpServletServer extends ExternalResource {

    private final int port;
    private Tomcat server;
    private final String webappDirLocation = "./src/test/webapp/";
    private File tmp = new File(webappDirLocation);
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
        server.setBaseDir(tmp.getAbsolutePath());

        Context context = server.addContext("", tmp.getAbsolutePath());
        context.addServletContainerInitializer(new ServletContainerInitializer() {
            @Override
            public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {
                System.out.println("testing...");
            }
        }, Collections.emptySet());

        createFile();

        Tomcat.addServlet( context, "servlet" , servlet);
        Tomcat.addServlet(context, "faces", new FacesServlet());
        context.addServletMappingDecoded("/*","servlet");
        context.addServletMappingDecoded("/test","servlet");
        context.addServletMappingDecoded("/faces/*", "faces");
        context.addServletMappingDecoded("*.xhtml", "faces");

        context.addWelcomeFile("/index.jsp");

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

    private void createFile() {
        File indexFile = new File(webappDirLocation + "index.jsp");
        File indexJSFFile = new File(webappDirLocation + "index.xhtml");
        try {
            if ((tmp.exists() || tmp.mkdir()) && indexFile.createNewFile() && indexJSFFile.createNewFile()) {
                BufferedWriter writer = new BufferedWriter(new FileWriter(indexFile));
                writer.append("Hello World!");
                writer.flush();
                writer.close();

                BufferedWriter writer1 = new BufferedWriter(new FileWriter(indexJSFFile));
                writer1.append("Hello World!");
                writer1.flush();
                writer1.close();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}