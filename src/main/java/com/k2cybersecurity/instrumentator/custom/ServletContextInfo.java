package com.k2cybersecurity.instrumentator.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ServletContextInfo {
    public static final String GET_CONTEXT_PATH = "getContextPath";
    public static final String GET_SERVER_INFO = "getServerInfo";
    public static final String GET_MAJOR_VERSION = "getMajorVersion";
    public static final String GET_MINOR_VERSION = "getMinorVersion";
    public static final String GET_REAL_PATH = "getRealPath";
    public static final String GET_SERVLET_CONTEXT_NAME = "getServletContextName";
    public static final String GET_RESOURCE_PATHS= "getResourcePaths";
    public static final String GET_RESOURCE= "getResource";
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

    @JsonIgnore
    private static ServletContextInfo instance;

    private Map<String, DeployedApplication> contextMap = new HashMap<>();

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

    public void processServletContext(Object servletContext, String contextPath, int serverPort) {
        String applicationName = StringUtils.EMPTY;
        String applicationDir = StringUtils.EMPTY;
        String serverInfo = StringUtils.EMPTY;

        Method getServletContextName = null;
        Method getRealPath = null;
        Method getServerInfo = null;
        Method getMajorVersion = null;
        Method getMinorVersion = null;

        DeployedApplication deployedApplication = new DeployedApplication();
        deployedApplication.setContextPath(contextPath);

        try {
            if (contextMap.containsKey(deployedApplication.getContextPath())) {
                if (contextMap.get(deployedApplication.getContextPath()).updatePorts(serverPort)) {
                    EventDispatcher.dispatch(contextMap.get(deployedApplication.getContextPath()), VulnerabilityCaseType.APP_INFO);
                }
                return;
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, ServletContextInfo.class.getName());
        }


        try {
            getServerInfo = servletContext.getClass().getMethod(GET_SERVER_INFO);
            getMajorVersion = servletContext.getClass().getMethod(GET_MAJOR_VERSION);
            getMinorVersion = servletContext.getClass().getMethod(GET_MINOR_VERSION);
            getRealPath = servletContext.getClass().getMethod(GET_REAL_PATH, String.class);
            getServletContextName = servletContext.getClass().getMethod(GET_SERVLET_CONTEXT_NAME);
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, ServletContextInfo.class.getName());
        }

        try {
            serverInfo = (String) getServerInfo.invoke(servletContext, null);
            setMajorServletVersion((Integer) getMajorVersion.invoke(servletContext, null));
            setMinorServletVersion((Integer) getMinorVersion.invoke(servletContext, null));

            applicationDir = processWebappPath(servletContext);
//            System.out.println("App Dir detected : " + applicationDir);
            applicationName = (String) getServletContextName.invoke(servletContext, null);

        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, ServletContextInfo.class.getName());
        }


        setServerInfo(serverInfo);

        deployedApplication.setAppName(applicationName);
        deployedApplication.setDeployedPath(applicationDir);
        deployedApplication.updatePorts(serverPort);

        // TODO: This application dir detection is still inaccurate as this brings the location of classloader & not application context root.
        //        Hence this misses the HTML part of the application.
        if (StringUtils.isBlank(deployedApplication.getDeployedPath())) {
            try {
                Method getClassLoader = servletContext.getClass().getMethod(GET_CLASS_LOADER);
                getClassLoader.setAccessible(true);
                ClassLoader classLoader = (ClassLoader) getClassLoader.invoke(servletContext, null);
                URL resPath = null;
                if (classLoader != null) {
                    resPath = classLoader.getResource(FORWARD_SLASH);
                    if (resPath == null) {
                        Object servletInstance = ThreadLocalHTTPServiceLock.getInstance().isTakenBy();
                        if (servletInstance != null) {
                            resPath = servletInstance.getClass().getProtectionDomain().getCodeSource().getLocation();
                        }
                    }

                    if (resPath != null) {
                        deployedApplication.setDeployedPath(resPath.toString());
                        if (StringUtils.startsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_FILE)) {
                            deployedApplication.setEmbedded(true);
                            deployedApplication.setDeployedPath(StringUtils.substringBetween(deployedApplication.getDeployedPath(), JAR_FILE, NOT));
                        } else {
                            deployedApplication.setDeployedPath(StringUtils.removeStart(deployedApplication.getDeployedPath(), FILE));
                            deployedApplication.setDeployedPath(StringUtils.substringBefore(deployedApplication.getDeployedPath(), WEB_INF));
                        }
                    }
                }
            } catch (Exception e) {
                logger.log(LogLevel.ERROR, ERROR, e, ServletContextInfo.class.getName());
            }
        }

        if (StringUtils.isNotBlank(deployedApplication.getDeployedPath())) {
            if (!StringUtils.equals(deployedApplication.getContextPath(), FORWARD_SLASH)
                    && !StringUtils.endsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_EXT)) {
                Path applicationPath = Paths.get(deployedApplication.getDeployedPath());
                deployedApplication.setDeployedPath(applicationPath.getParent().toString());
            }
        }

//
//        if (StringUtils.equals(deployedApplication.getAppName(), ROOT)){
//            if (StringUtils.isBlank(contextPath) || StringUtils.equals(deployedApplication.getContextPath(), FORWARD_SLASH)) {
//                deployedApplication.setAppName(ROOT);
//            } else if (StringUtils.endsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_EXT)) {
//                deployedApplication.setAppName(Paths.get(deployedApplication.getDeployedPath()).getFileName().toString());
//            } else {
//                deployedApplication.setAppName(StringUtils.removeStart(StringUtils.replace(deployedApplication.getContextPath(), FORWARD_SLASH, REPLACEMENT),
//                        REPLACEMENT));
//                deployedApplication.setAppName(StringUtils.removeEnd(deployedApplication.getAppName(), REPLACEMENT));
//            }
//        }

        if (StringUtils.equals(deployedApplication.getAppName(), ROOT)){
            if (StringUtils.endsWithIgnoreCase(deployedApplication.getDeployedPath(), JAR_EXT)) {
                deployedApplication.setAppName(Paths.get(deployedApplication.getDeployedPath()).getFileName().toString());
            }
            else if(!StringUtils.equals(deployedApplication.getContextPath(), FORWARD_SLASH)){
                deployedApplication.setAppName(StringUtils.removeStart(StringUtils.replace(deployedApplication.getContextPath(), FORWARD_SLASH, REPLACEMENT),
                        REPLACEMENT));
                deployedApplication.setAppName(StringUtils.removeEnd(deployedApplication.getAppName(), REPLACEMENT));
            }
        }

        this.contextMap.put(deployedApplication.getContextPath(), deployedApplication);
        if (!deployedApplication.isEmpty()) {
            EventDispatcher.dispatch(deployedApplication, VulnerabilityCaseType.APP_INFO);
            logger.log(LogLevel.INFO, "Servlet info populated & sent : " + deployedApplication, ServletContextInfo.class.getName());
        }
//
//		System.out.println("==========================================================================================");
//		System.out.println("New Servlet Context found : ");
//		System.out.println("Details  : " + deployedApplication);
//		System.out.println("Server Info  : " + serverInfo);
//		System.out.println("Major Servlet Version  : " + majorServletVersion);
//		System.out.println("Minor Servlet Version  : " + minorServletVersion);
//        Object servletInstance = ThreadLocalHTTPServiceLock.getInstance().isTakenBy();
//        if (servletInstance != null) {
//            System.out.println("XYZ Path :" + servletInstance.getClass().getProtectionDomain().getCodeSource().getLocation());
//        }
//		System.out.println("==========================================================================================");

    }

    private String processWebappPath(Object servletContext) {
        String appPath = StringUtils.EMPTY;
        try {
            Method getResource = servletContext.getClass().getMethod(GET_RESOURCE, String.class);
            URL appPathURL = (URL) getResource.invoke(servletContext, "/META-INF/MANIFEST.MF");
            appPath = Paths.get(appPathURL.getPath()).getParent().getParent().toString();
        } catch (Exception e){
            logger.log(LogLevel.ERROR, ERROR, e, ServletContextInfo.class.getName());
        }
        return appPath;
    }

}
