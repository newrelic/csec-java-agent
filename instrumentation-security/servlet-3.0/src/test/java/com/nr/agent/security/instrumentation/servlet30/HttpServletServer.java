package com.nr.agent.security.instrumentation.servlet30;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.junit.rules.ExternalResource;

import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
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
        try (ServerSocket socket = new ServerSocket(0);){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port ");
        }
    }

    private void startServer () throws Exception {
        TomcatURLStreamHandlerFactory.disable();

        server = new Tomcat();
        server.setPort(port);

        tmp = new File("./tmp");
        server.setBaseDir(tmp.getAbsolutePath());

        Context context = server.addContext("", tmp.getAbsolutePath());
        context.addServletContainerInitializer(new ServletContainerInitializer() {
            @Override
            public void onStartup(Set<Class<?>> c, ServletContext ctx){
                System.out.println("testing...");
            }
        }, Collections.emptySet());

        Tomcat.addServlet(context, "servlet", new MyServlet());
        context.addServletMappingDecoded("/*","servlet");
        context.addServletMappingDecoded("/test","servlet");

        final Connector connector = new Connector();
        connector.setPort(port);
        server.getService().addConnector(connector);

        server.start();
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
    }

    public URI getEndPoint() throws URISyntaxException {
        return new URI("http://localhost:" + port + "/test");
    }
}
class MyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        super.doGet(req, resp);
    }
}