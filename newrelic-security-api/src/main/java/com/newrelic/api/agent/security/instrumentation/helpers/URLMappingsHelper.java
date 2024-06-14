package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class URLMappingsHelper {
    public static final String subResourceSegment = "/*";
    private static Set<ApplicationURLMapping> mappings = ConcurrentHashMap.newKeySet();
    private static final Set<String> defaultHandlers = new HashSet<String>() {{
        add("org.eclipse.jetty.jsp.JettyJspServlet");
        add("org.eclipse.jetty.servlet.ServletHandler$Default404Servlet");
        add("org.glassfish.jersey.servlet.ServletContainer");
        add("org.apache.jasper.servlet.JspServlet");
        add("org.apache.catalina.servlets.DefaultServlet");
        add("org.eclipse.jetty.servlet.DefaultServlet");
        add("grails.plugin.databasemigration.DbdocController");
    }};

    public static Set<ApplicationURLMapping> getApplicationURLMappings() {
        return mappings;
    }

    private static Set<Integer> handlers = ConcurrentHashMap.newKeySet();

    public static Set<Integer> getHandlersHash() {
        return handlers;
    }

    public static void addApplicationURLMapping(ApplicationURLMapping mapping) {
        if (mapping.getHandler() == null || (mapping.getHandler() != null && !defaultHandlers.contains(mapping.getHandler()))) {
            mappings.add(mapping);
        }
        if (mapping.getHandler() != null){
            handlers.add(mapping.getHandler().hashCode());
        }
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
}
