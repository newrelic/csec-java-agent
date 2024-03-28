package com.nr.instrumentation.resteasy3.test;

import com.nr.instrumentation.resteasy3.app.CustomerLocatorResource;
import com.nr.instrumentation.resteasy3.app.TestMapping;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.jboss.resteasy.plugins.server.servlet.ResteasyBootstrap;

import javax.ws.rs.core.Application;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

public class TestApplication extends Application {

    private final Set<Object> classes = new HashSet<>();
    private static Tomcat tomcat;
    private static int port;
    private static final File tmp = new File("./tmp");

    public TestApplication() {
        classes.add(new CustomerLocatorResource());
        classes.add(new TestMapping());
    }

    @Override
    public Set<Object> getSingletons() {
        return classes;
    }

    public static void startServer() throws LifecycleException {
        TomcatURLStreamHandlerFactory.disable();
        getRandomPort();

        tomcat = new Tomcat();
        tomcat.setPort(port);

        String workingDir = tmp.getAbsolutePath();

        tomcat.setBaseDir(workingDir);
        tomcat.getHost().setAppBase(workingDir);

        Context context = tomcat.addContext("/api", workingDir);
        context.addApplicationListener(ResteasyBootstrap.class.getName());

        Tomcat.addServlet(context, "resteasy-servlet", new HttpServletDispatcher());
        context.addParameter("resteasy.scan", "true");
        context.addParameter(Application.class.getName(), TestApplication.class.getName());
        context.addServletMappingDecoded("/*", "resteasy-servlet");

        final Connector connector = new Connector();
        connector.setPort(port);

        tomcat.getService().addConnector(connector);
        tomcat.start();
    }

    public static void stopServer() {
        if (tomcat.getServer() != null && tomcat.getServer().getState() != LifecycleState.DESTROYED) {
            try {
                if (tomcat.getServer().getState() != LifecycleState.STOPPED) {
                    tomcat.stop();
                }
                tomcat.destroy();
                FileUtils.forceDelete(tmp);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static URL getEndPoint(String path) throws MalformedURLException {
        return new URL("http://localhost:" + port + "/api/" + path);
    }
    private static void getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            port = socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port "+ port);
        }
    }
}
