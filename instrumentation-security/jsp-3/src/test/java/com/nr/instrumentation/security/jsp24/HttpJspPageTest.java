package com.nr.instrumentation.security.jsp24;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.jsp.HttpJspPage;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "jakarta.servlet.jsp")
public class HttpJspPageTest {
    private static final int port = getRandomPort();
    private static Tomcat server;
    private static final File WEB_APP = new File("./src/test/webapp/");

    @BeforeClass
    public static void start() throws LifecycleException{
        startServer();
    }
    @AfterClass
    public static void stop() throws Exception{
        stopServer();
    }

    @Test
    public void testService() throws Exception {
        service();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user Level Service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Trace(dispatcher = true)
    private void service() throws IOException, URISyntaxException {
        URL u = new URI(String.format("http://localhost:%d/", port)).toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestMethod("GET");

        conn.connect();
        conn.getResponseCode();
    }

    private static void startServer() throws LifecycleException {
        TomcatURLStreamHandlerFactory.disable();
        server = new Tomcat();
        server.setPort(port);
        server.setBaseDir(WEB_APP.getAbsolutePath());
        Context context = server.addContext("", WEB_APP.getAbsolutePath());
        Tomcat.addServlet( context, "servlet" , new DummyJsp());
        context.addServletMappingDecoded("/*","servlet");
        server.getConnector();
        server.start();
    }

    private static void stopServer() throws Exception{
        if (server.getServer() != null && server.getServer().getState() != LifecycleState.DESTROYED) {
            server.stop();
            FileUtils.forceDelete(WEB_APP);
            server.destroy();
        }
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

    private static class DummyJsp extends HttpServlet implements HttpJspPage {
        @Override
        public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            _jspService(request, response);
        }
        public void _jspService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        }
        public void jspDestroy() {
        }
        public void jspInit() {
        }
    }
}
