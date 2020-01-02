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

    public void putContextInfo(String contextPath, String applicationDir) {
        String appPath = StringUtils.EMPTY;
        String appName = StringUtils.EMPTY;
        if(StringUtils.isBlank(contextPath)){
            appName = "ROOT";
            appPath = applicationDir;
        } else {
            Path applicationPath = Paths.get(applicationDir);
            if (StringUtils.equals(contextPath, "/")) {
                appPath = applicationPath.toString();
                appName = applicationPath.getFileName().toString();
            } else {
                appPath = applicationPath.getParent().toString();
                appName = applicationPath.getFileName().toString();
            }
        }
        contextMap.put(contextPath, new DeployedApplication(contextPath, appName, appPath));
    }

    public void putContextInfo(String contextPath, String applicationDir, String appName) {
        String appPath = StringUtils.EMPTY;

        if(StringUtils.isBlank(contextPath)){
            if(StringUtils.isBlank(appName)){
                appName = "ROOT";
            }
            appPath = applicationDir;
        } else {
            Path applicationPath = Paths.get(applicationDir);
            if (StringUtils.equals(contextPath, "/")) {
                appPath = applicationPath.toString();
            } else {
                appPath = applicationPath.getParent().toString();
            }
        }
        DeployedApplication app = new DeployedApplication(contextPath, appName, appPath);
        contextMap.put(contextPath, app);
        EventDispatcher.dispatch(new DeployedApplication(app), VulnerabilityCaseType.APP_INFO);
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

    public void processServletContext(Object servletContext, String contextPath) {
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

        if (StringUtils.isNotBlank(applicationName)) {
            putContextInfo(contextPath, applicationDir, applicationName);
        } else {
            putContextInfo(contextPath, applicationDir);
        }

        if (StringUtils.isNotBlank(serverInfo)) {
            setServerInfo(serverInfo);
        }
        System.out.println("Current servlet context map : " + ServletContextInfo.getInstance());
    }
}
