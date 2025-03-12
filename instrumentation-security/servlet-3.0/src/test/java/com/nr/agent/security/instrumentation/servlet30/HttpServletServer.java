package com.nr.agent.security.instrumentation.servlet30;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.junit.rules.ExternalResource;

import javax.faces.webapp.FacesServlet;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    private final File tmp = new File(webappDirLocation);
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
        createFile();

        server = new Tomcat();
        server.setPort(port);

        server.setBaseDir(webappDirLocation);
        server.addWebapp("", tmp.getAbsolutePath());

        Context context = server.addContext("/tmp", tmp.getAbsolutePath());
        context.addServletContainerInitializer(new ServletContainerInitializer() {
            @Override
            public void onStartup(Set<Class<?>> c, ServletContext ctx){
                System.out.println("testing...");
            }
        }, Collections.emptySet());

        Tomcat.addServlet(context, "servlet", new MyServlet());
        Tomcat.addServlet(context, "faces", new FacesServlet());
        context.setAddWebinfClassesResources(true);
        context.addServletMappingDecoded("/faces/*", "faces");
        context.addServletMappingDecoded("*.xhtml", "faces");
        context.addWelcomeFile("/index.jsp");
        context.addServletMappingDecoded("/servlet/*","servlet");

        final Connector connector = new Connector();
        connector.setPort(port);
        server.getService().addConnector(connector);

        server.start();
    }

    private void createFile() {
        File indexFile = new File(webappDirLocation + "index.jsp");
        File indexJSFFile = new File(webappDirLocation + "index.xhtml");
        try {
            if (tmp.mkdir() && indexFile.createNewFile() && indexJSFFile.createNewFile()) {
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