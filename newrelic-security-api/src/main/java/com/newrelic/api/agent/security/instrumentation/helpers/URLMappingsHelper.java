package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.RouteSegment;
import com.newrelic.api.agent.security.schema.RouteSegments;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

public class URLMappingsHelper {
    public static final String SEPARATOR = "/";

    public static final String WILDCARD = "*";

    public static final String subResourceSegment = "/*";

    private static final Set<ApplicationURLMapping> mappings = ConcurrentHashMap.newKeySet();

    private static final Set<String> defaultHandlers = new HashSet<String>() {{
        add("org.eclipse.jetty.jsp.JettyJspServlet");
        add("org.eclipse.jetty.servlet.ServletHandler$Default404Servlet");
        add("org.glassfish.jersey.servlet.ServletContainer");
        add("org.apache.jasper.servlet.JspServlet");
        add("org.apache.catalina.servlets.DefaultServlet");
        add("org.eclipse.jetty.servlet.DefaultServlet");
        add("grails.plugin.databasemigration.DbdocController");
        add("org.apache.cxf.transport.servlet.CXFServlet");
        add("javax.faces.webapp.FacesServlet");
        add("jakarta.faces.webapp.FacesServlet");
        add("weblogic.servlet.JSPServlet");
        add("weblogic.servlet.FileServlet");
        add("weblogic.management.rest.JerseyServlet");
        add("com.caucho.jsp.XtpServlet");
        add("com.caucho.jsp.JspServlet");
        add("com.caucho.xtpdoc.ResinDocServlet");
        add("com.caucho.quercus.servlet.QuercusServlet");
        add("com.caucho.servlets.FileServlet");
        add("com.caucho.doc.JavadocRedirectServlet");
        add("com.caucho.xtpdoc.ReferenceServlet");
        add("com.caucho.doc.ViewFileServlet");
        add("org.springframework.web.servlet.DispatcherServlet");
        add("org.eclipse.jetty.ee8.jsp.JettyJspServlet");
        add("org.eclipse.jetty.ee8.servlet.DefaultServlet");
        add("org.eclipse.jetty.servlet.NoJspServlet");
        add("org.codehaus.groovy.grails.web.servlet.GrailsDispatcherServlet");
        add("org.codehaus.groovy.grails.web.pages.GroovyPagesServlet");
        add("org.codehaus.groovy.grails.web.servlet.ErrorHandlingServlet");
        add("org.jboss.resteasy.plugins.server.servlet.HttpServlet30Dispatcher");
    }};

    public static Set<ApplicationURLMapping> getApplicationURLMappings() {
        return mappings;
    }

    private static final Set<Integer> handlers = ConcurrentHashMap.newKeySet();

    private static final Set<RouteSegments> routeSegments = new TreeSet<>(new RouteComparator());

    public static Set<Integer> getHandlersHash() {
        return handlers;
    }

    public static Set<RouteSegments> getRouteSegments() {
        return routeSegments;
    }

    public static void addApplicationURLMapping(ApplicationURLMapping mapping) {
        if (mapping.getHandler() != null && defaultHandlers.contains(mapping.getHandler())){
            return;
        }
        mappings.add(mapping);
        generateRouteSegments(mapping.getPath());
        if (mapping.getHandler() != null && StringUtils.isNotBlank(mapping.getHandler())){
            handlers.add(mapping.getHandler().hashCode());
        }
        NewRelicSecurity.getAgent().reportURLMapping();
    }

    private synchronized static void generateRouteSegments(String endpoint) {
        try {
            List<RouteSegment> segments = new ArrayList<>();
            Path uri = Paths.get(endpoint).normalize();
            while (uri.getParent() != null){
                String path = uri.getFileName().toString();
                uri = uri.getParent();
                if (StringUtils.equals(path, StringUtils.SEPARATOR)){
                    continue;
                }
                RouteSegment routeSegment = new RouteSegment(path, isPathParam(path), false);
                segments.add(routeSegment);
            }
            routeSegments.add(new RouteSegments(endpoint, segments));
        } catch (Exception e) {
        }
    }

    private static boolean isPathParam(String path) {
        return StringUtils.startsWithAny(path, ":", "$") ||
                StringUtils.equals(path,"*") ||
                (StringUtils.startsWith(path, "{") && StringUtils.endsWith(path, "}"));
    }

    private static boolean allowMultiSegments(String path) {
        return StringUtils.equals(path, "*");
    }

    public static List<String> getSegments(String endpoint) {
        List<String> segments = new ArrayList<>();
        Path uri = Paths.get(endpoint).normalize();
        while (uri.getParent() != null) {
            String path = uri.getFileName().toString();
            uri = uri.getParent();
            if (StringUtils.isNotBlank(path) && !StringUtils.equals(path, StringUtils.SEPARATOR)) {
                segments.add(path);
            }
        }
        return segments;
    }

    public static int getSegmentCount(String path){
        Path normalizedPath = Paths.get(StringUtils.prependIfMissing(StringUtils.removeEnd(path, StringUtils.SEPARATOR), StringUtils.SEPARATOR)).normalize();
        int i = 0;
        while (normalizedPath.getParent() != null){
            normalizedPath = normalizedPath.getParent();
            i++;
        }
        return i;
    }

    public static void removeApplicationURLMapping(String method, String path) {
        if (!mappings.isEmpty()) {
            mappings.remove(new ApplicationURLMapping(method, path));
        }
    }
}
