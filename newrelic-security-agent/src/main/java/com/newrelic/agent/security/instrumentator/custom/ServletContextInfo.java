package com.newrelic.agent.security.instrumentator.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.DeployedApplication;
import com.newrelic.agent.security.intcodeagent.models.javaagent.HttpRequestBean;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Enumeration;

public class ServletContextInfo {
    public static final String GET_CONTEXT_PATH = "getContextPath";
    public static final String GET_SERVER_INFO = "getServerInfo";
    public static final String GET_MAJOR_VERSION = "getMajorVersion";
    public static final String GET_MINOR_VERSION = "getMinorVersion";
    public static final String GET_REAL_PATH = "getRealPath";
    public static final String GET_SERVLET_CONTEXT_NAME = "getServletContextName";
    public static final String GET_RESOURCE_PATHS = "getResourcePaths";
    public static final String GET_RESOURCE = "getResource";
    public static final String GET_RESOURCES = "getResources";
    public static final String ERROR = "Error : ";
    public static final String GET_CLASS_LOADER = "getClassLoader";
    public static final String FORWARD_SLASH = "/";
    public static final String FILE = "file:";
    public static final String WEB_INF = "/WEB-INF";
    public static final String JAR_FILE = "jar:file:";
    public static final String JAR_EXT = ".jar";
    public static final String NOT = "!";
    public static final String ROOT = "ROOT";
    public static final String REPLACEMENT = "_";
    private static final String COLON = " - ";
    public static final String META_INF_MANIFEST_MF = "/META-INF/MANIFEST.MF";
    public static final String INF = "-INF";
    public static final String WEBAPP_PATH_DETECTED_USING_METHOD_1 = "Webapp path detected using method 1 : ";
    public static final String WEBAPP_PATH_DETECTED_USING_METHOD_2 = "Webapp path detected using method 2 : ";
    public static final String WEBAPP_PATH_DETECTED_USING_METHOD_3 = "Webapp path detected using method 3 : ";
    public static final String SERVLET_INFO_POPULATED_SENT = "Servlet info populated & sent : ";
    public static final String CLASSES_STR = "/classes/";
    public static final String CLASSES_STR_1 = "/classes!";
    public static final String L_1 = "L1 : ";
    public static final String APPLICATION = "application";
    public static final String CAUSE = " CAUSE :";

    @JsonIgnore
    private static ServletContextInfo instance;

    private String serverInfo = StringUtils.EMPTY;

    private Integer majorServletVersion;

    private Integer minorServletVersion;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

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

    public String getServerInfo() {
        return serverInfo;
    }

    public void setServerInfo(String serverInfo) {
        if (StringUtils.isBlank(serverInfo)) {
            this.serverInfo = StringUtils.EMPTY;
        } else {
            this.serverInfo = serverInfo;
        }
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

    public boolean processServletContext(HttpRequestBean httpRequestBean, DeployedApplication deployedApplication) {
        String contextPath = httpRequestBean.getContextPath();
        Object servletContext = httpRequestBean.getServletContextObject();
        int serverPort = httpRequestBean.getServerPort();
        String applicationName = StringUtils.EMPTY;
        String serverInfo = StringUtils.EMPTY;

        Method getServletContextName = null;
        Method getServerInfo = null;
        Method getMajorVersion = null;
        Method getMinorVersion = null;

        deployedApplication.setContextPath(contextPath);

        // TODO: Lets separate these out just in case.
        try {
            getServerInfo = servletContext.getClass().getMethod(GET_SERVER_INFO);
            getMajorVersion = servletContext.getClass().getMethod(GET_MAJOR_VERSION);
            getMinorVersion = servletContext.getClass().getMethod(GET_MINOR_VERSION);
            getServletContextName = servletContext.getClass().getMethod(GET_SERVLET_CONTEXT_NAME);
        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR + e.getMessage() + CAUSE + e.getCause(), ServletContextInfo.class.getName());
            logger.log(LogLevel.DEBUG, ERROR, e, ServletContextInfo.class.getName());
        }

        try {
            serverInfo = (String) getServerInfo.invoke(servletContext, null);
            setMajorServletVersion((Integer) getMajorVersion.invoke(servletContext, null));
            setMinorServletVersion((Integer) getMinorVersion.invoke(servletContext, null));
            applicationName = (String) getServletContextName.invoke(servletContext, null);

        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR + e.getMessage() + CAUSE + e.getCause(), ServletContextInfo.class.getName());
            logger.log(LogLevel.DEBUG, ERROR, e, ServletContextInfo.class.getName());
        }


        setServerInfo(serverInfo);

        deployedApplication.setAppName(applicationName);
        deployedApplication.getPorts().add(serverPort);


        if (StringUtils.isNotBlank(deployedApplication.getDeployedPath())) {

            if (StringUtils.startsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_FILE)) {
                deployedApplication.setEmbedded(true);
                deployedApplication.setDeployedPath(StringUtils.substringBetween(deployedApplication.getDeployedPath(), JAR_FILE, NOT));
            } else if (StringUtils.startsWithIgnoreCase(deployedApplication.getDeployedPath(), FILE)) {
                deployedApplication.setDeployedPath(StringUtils.substringBetween(deployedApplication.getDeployedPath(), FILE, NOT));
            }

            String intermediatePath = deployedApplication.getDeployedPath();
            if (StringUtils.contains(intermediatePath, INF + File.separator)) {
                intermediatePath = StringUtils.substringBefore(intermediatePath, INF + File.separator);
                deployedApplication.setDeployedPath(new File(intermediatePath).getParent());
            }

            if (StringUtils.endsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_EXT)) {
                deployedApplication.setEmbedded(true);
            }

        } else {
            return false;
        }

        if (StringUtils.equalsAnyIgnoreCase(deployedApplication.getAppName(), ROOT, APPLICATION)) {
            if (StringUtils.endsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_EXT)) {
                deployedApplication.setAppName(Paths.get(deployedApplication.getDeployedPath()).getFileName().toString());
            } else if (!StringUtils.equals(deployedApplication.getContextPath(), FORWARD_SLASH)) {
                deployedApplication.setAppName(StringUtils.removeStart(StringUtils.replace(deployedApplication.getContextPath(), FORWARD_SLASH, REPLACEMENT),
                        REPLACEMENT));
                deployedApplication.setAppName(StringUtils.removeEnd(deployedApplication.getAppName(), REPLACEMENT));
            }
        }


        if (!deployedApplication.isEmpty()) {
            logger.log(LogLevel.INFO, SERVLET_INFO_POPULATED_SENT + deployedApplication, ServletContextInfo.class.getName());
        }

        return !deployedApplication.isEmpty();
    }

    private String processWebappPath(Object servletContext) {
        String appPath = StringUtils.EMPTY;

        // Detection 1: Using classloader.getResource
        try {
            Method getClassLoader = servletContext.getClass().getMethod(GET_CLASS_LOADER);
            getClassLoader.setAccessible(true);
            ClassLoader classLoader = (ClassLoader) getClassLoader.invoke(servletContext, null);

            if (classLoader != null) {
                Enumeration<URL> appPathURLEnum = classLoader.getResources(StringUtils.EMPTY);
                while (appPathURLEnum != null && appPathURLEnum.hasMoreElements()) {
                    URL app = appPathURLEnum.nextElement();
//                    System.out.println("L1 : " + app.getPath());
                    logger.log(LogLevel.DEBUG, L_1 + app.getPath(), ServletContextInfo.class.getName());

                    if (StringUtils.containsAny(app.getPath(), CLASSES_STR, CLASSES_STR_1)) {
                        appPath = app.getPath();
                        break;
                    }
                }
                if (StringUtils.isNotBlank((appPath))) {
                    logger.log(LogLevel.DEBUG, WEBAPP_PATH_DETECTED_USING_METHOD_1 + appPath, ServletContextInfo.class.getName());
                    return appPath;
                }
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, ServletContextInfo.class.getName());
        }

        return appPath;
    }

}
