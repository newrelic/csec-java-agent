package com.k2cybersecurity.instrumentator.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class ServletContextInfo {
    @JsonIgnore
    private static ServletContextInfo instance;

    private Map<String, DeployedApplication> contextMap = new HashMap<>();

    private String serverInfo = StringUtils.EMPTY;

    private Integer majorServletVersion;

    private Integer minorServletVersion;


    private ServletContextInfo() {
    }

    public static ServletContextInfo getInstance() {
        if (instance == null) {
            instance = new ServletContextInfo();
        }
        return instance;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public void putContextInfo(String contextPath, String applicationDir, int serverPort) {
        DeployedApplication app = new DeployedApplication();
        app.updatePorts(serverPort);
        app.setServerInfo(serverInfo);
        if(StringUtils.isBlank(contextPath)){
            app.setContextPath("/");
            app.setAppName("ROOT");
            app.setDeployedPath(applicationDir);
        } else {
            Path applicationPath = Paths.get(applicationDir);
            if (StringUtils.equals(contextPath, "/")) {
                app.setContextPath(contextPath);
                app.setAppName(applicationPath.getFileName().toString());
                app.setDeployedPath(applicationPath.toString());
            } else {
                app.setContextPath(contextPath);
                app.setAppName(applicationPath.getFileName().toString());
                app.setDeployedPath(applicationPath.getParent().toString());
            }
        }
        contextMap.put(contextPath, app);
        EventDispatcher.dispatch(app, VulnerabilityCaseType.APP_INFO);
    }

    public void putContextInfo(String contextPath, String applicationDir, String appName, int serverPort) {
        DeployedApplication app = new DeployedApplication();
        app.updatePorts(serverPort);
        app.setServerInfo(serverInfo);
        if(StringUtils.isBlank(appName)){
            app.setAppName("ROOT");
        } else {
            app.setAppName(appName);
        }

        if(StringUtils.isBlank(contextPath)){
            app.setContextPath("/");
            app.setDeployedPath(applicationDir);
        } else {
            Path applicationPath = Paths.get(applicationDir);
            if (StringUtils.equals(contextPath, "/")) {
                app.setDeployedPath(applicationPath.toString());
            } else {
                app.setDeployedPath(applicationPath.getParent().toString());
            }
            app.setContextPath(contextPath);
        }
        contextMap.put(contextPath, app);
        EventDispatcher.dispatch(app, VulnerabilityCaseType.APP_INFO);
    }

    public String getServerInfo() {
        return serverInfo;
    }

    public void setServerInfo(String serverInfo) {
        this.serverInfo = serverInfo;
    }

    public Integer getMajorServletVersion() {
        return majorServletVersion;
    }

    public void setMajorServletVersion(Integer majorServletVersion) {
        this.majorServletVersion = majorServletVersion;
    }

    public Integer getMinorServletVersion() {
        return minorServletVersion;
    }

    public void setMinorServletVersion(Integer minorServletVersion) {
        this.minorServletVersion = minorServletVersion;
    }

    public void processServletContext(Object servletContext, String contextPath, int serverPort) {
        String applicationName = StringUtils.EMPTY;
        String applicationDir = StringUtils.EMPTY;
        String serverInfo = StringUtils.EMPTY;

        Method getServletContextName = null;
        Method getContextPath = null;
        Method getRealPath = null;
        Method getServerInfo = null;
        Method getMajorVersion = null;
        Method getMinorVersion = null;

        try {
            if (contextMap.containsKey(contextPath)) {
                if(contextMap.get(contextPath).updatePorts(serverPort)){
                    EventDispatcher.dispatch(contextMap.get(contextPath), VulnerabilityCaseType.APP_INFO);
                }
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getContextPath = servletContext.getClass().getMethod("getContextPath");
            getServerInfo = servletContext.getClass().getMethod("getServerInfo");
            getMajorVersion = servletContext.getClass().getMethod("getMajorVersion");
            getMinorVersion = servletContext.getClass().getMethod("getMinorVersion");
            getRealPath = servletContext.getClass().getMethod("getRealPath", String.class);
            getServletContextName = servletContext.getClass().getMethod("getServletContextName");
        } catch (Exception e) {
            System.out.println("Not found : " + e.getCause());
            e.printStackTrace();
        }
        try {
            contextPath = (String) getContextPath.invoke(servletContext, null);
            serverInfo = (String) getServerInfo.invoke(servletContext, null);
            setMajorServletVersion((Integer) getMajorVersion.invoke(servletContext, null));
            setMinorServletVersion((Integer) getMinorVersion.invoke(servletContext, null));
            applicationDir = (String) getRealPath.invoke(servletContext, contextPath);
            applicationName = (String) getServletContextName.invoke(servletContext, null);

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("==========================================================================================");
        System.out.println("Context details found : ");
        System.out.println("Path : " + contextPath);
        System.out.println("Major Version : " + majorServletVersion);
        System.out.println("Minor Version : " + minorServletVersion);
        System.out.println("Server Info : "+ serverInfo);
        System.out.println("Application Dir : " +applicationDir );
        System.out.println("Application Name : " + applicationName);
        System.out.println("==========================================================================================");

        if (StringUtils.isNotBlank(serverInfo)) {
            setServerInfo(serverInfo);
        }

        if(StringUtils.isBlank(contextPath)){
            try {
                Method getClassLoader = servletContext.getClass().getMethod("getClassLoader");
                getClassLoader.setAccessible(true);
                ClassLoader classLoader = (ClassLoader) getClassLoader.invoke(servletContext, null);
                if(classLoader != null) {
                    applicationDir = classLoader.getResource("").toString();
                    if(StringUtils.startsWithIgnoreCase(applicationDir, "file:" )) {
                        applicationDir = StringUtils.removeStart(applicationDir, "file:");
                    } else if(StringUtils.startsWithIgnoreCase(applicationDir, "jar:file:" )){
                        applicationDir = StringUtils.substringBetween(applicationDir, "jar:file:", "!");
                    }
                } else {
                    System.out.println("Unable to get the application directory. Suspicion is that this is an embedded application.");
                    applicationDir = StringUtils.EMPTY;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }


        }


        if (StringUtils.isNotBlank(applicationName)) {
            putContextInfo(contextPath, applicationDir, applicationName, serverPort);
        } else {
            putContextInfo(contextPath, applicationDir, serverPort);
        }


        System.out.println("Current servlet context map : " + ServletContextInfo.getInstance());
    }
}
