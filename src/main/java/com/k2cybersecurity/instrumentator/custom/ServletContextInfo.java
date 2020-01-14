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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class ServletContextInfo {
	public static final String GET_CONTEXT_PATH = "getContextPath";
	public static final String GET_SERVER_INFO = "getServerInfo";
	public static final String GET_MAJOR_VERSION = "getMajorVersion";
	public static final String GET_MINOR_VERSION = "getMinorVersion";
	public static final String GET_REAL_PATH = "getRealPath";
	public static final String GET_SERVLET_CONTEXT_NAME = "getServletContextName";
	public static final String ERROR = "Error : ";
	public static final String GET_CLASS_LOADER = "getClassLoader";
	public static final String FORWARD_SLASH = "/";
	public static final String FILE = "file:";
	public static final String WEB_INF = "/WEB-INF";
	public static final String JAR_FILE = "jar:file:";
	public static final String NOT = "!";
	public static final String ROOT = "ROOT";
	public static final String REPLACEMENT = "_";
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

//    public void putContextInfo(String contextPath, String applicationDir, int serverPort) {
//        DeployedApplication app = new DeployedApplication();
//        app.updatePorts(serverPort);
//        app.setServerInfo(serverInfo);
//        if(StringUtils.isBlank(contextPath)){
//            app.setContextPath("/");
//            app.setAppName("ROOT");
//            app.setDeployedPath(applicationDir);
//        } else {
//            Path applicationPath = Paths.get(applicationDir);
//            if (StringUtils.equals(contextPath, "/")) {
//                app.setContextPath(contextPath);
//                app.setAppName(applicationPath.getFileName().toString());
//                app.setDeployedPath(applicationPath.toString());
//            } else {
//                app.setContextPath(contextPath);
//                app.setAppName(applicationPath.getFileName().toString());
//                app.setDeployedPath(applicationPath.getParent().toString());
//            }
//        }
//        contextMap.put(contextPath, app);
//        EventDispatcher.dispatch(app, VulnerabilityCaseType.APP_INFO);
//    }

    public void putContextInfo(String contextPath, String applicationDir, String appName, int serverPort) {
        DeployedApplication app = new DeployedApplication();
        app.updatePorts(serverPort);
        app.setServerInfo(serverInfo);
        if(StringUtils.isBlank(appName)){
            app.setAppName(ROOT);
        } else {
            app.setAppName(appName);
        }

        if(StringUtils.isBlank(contextPath)){
            app.setContextPath(FORWARD_SLASH);
            app.setDeployedPath(applicationDir);
        } else {
            Path applicationPath = Paths.get(applicationDir);
            if (StringUtils.equals(contextPath, FORWARD_SLASH)) {
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
            logger.log(LogLevel.ERROR, ERROR + e, ServletContextInfo.class.getName());
        }
        try {
            getContextPath = servletContext.getClass().getMethod(GET_CONTEXT_PATH);
            getServerInfo = servletContext.getClass().getMethod(GET_SERVER_INFO);
            getMajorVersion = servletContext.getClass().getMethod(GET_MAJOR_VERSION);
            getMinorVersion = servletContext.getClass().getMethod(GET_MINOR_VERSION);
            getRealPath = servletContext.getClass().getMethod(GET_REAL_PATH, String.class);
            getServletContextName = servletContext.getClass().getMethod(GET_SERVLET_CONTEXT_NAME);

		} catch (Exception e) {
//            System.out.println("Not found : " + e.getCause());
//            e.printStackTrace();
        }
        try {
            contextPath = (String) getContextPath.invoke(servletContext, null);
            serverInfo = (String) getServerInfo.invoke(servletContext, null);
            setMajorServletVersion((Integer) getMajorVersion.invoke(servletContext, null));
            setMinorServletVersion((Integer) getMinorVersion.invoke(servletContext, null));
            applicationDir = (String) getRealPath.invoke(servletContext, contextPath);
            applicationName = (String) getServletContextName.invoke(servletContext, null);

        } catch (Exception e) {
        	logger.log(LogLevel.ERROR, ERROR + e, ServletContextInfo.class.getName());
        }


		if (StringUtils.isNotBlank(serverInfo)) {
            setServerInfo(serverInfo);
        }

        // TODO: This application dir detection is still inaccurate as this brings the location of classloader & not application context root.
		//        Hence this misses the HTML part of the application.
		boolean isEmbedded = false;
		if(StringUtils.isBlank(applicationDir)){
			try {
				Method getClassLoader = servletContext.getClass().getMethod(GET_CLASS_LOADER);
				getClassLoader.setAccessible(true);
				ClassLoader classLoader = (ClassLoader) getClassLoader.invoke(servletContext, null);
				if(classLoader != null) {
					applicationDir = classLoader.getResource(FORWARD_SLASH).toString();
//					System.out.println("Application dir from resource : " + applicationDir);
					if(StringUtils.startsWithIgnoreCase(applicationDir, FILE)) {
						applicationDir = StringUtils.removeStart(applicationDir, FILE);
						applicationDir = StringUtils.substringBefore(applicationDir, WEB_INF);
					} else if(StringUtils.startsWithIgnoreCase(applicationDir, JAR_FILE)){
						isEmbedded = true;
						applicationDir = StringUtils.substringBetween(applicationDir, JAR_FILE, NOT);
					}
				} else {
//					System.out.println("Unable to get the application directory. Suspicion is that this is an embedded application.");
					applicationDir = StringUtils.EMPTY;
				}
			} catch (Exception e) {
				logger.log(LogLevel.ERROR, ERROR + e, ServletContextInfo.class.getName());
			}


		}

        if(StringUtils.isBlank(contextPath)){
        	contextPath = FORWARD_SLASH;
        }

		if(StringUtils.isBlank(applicationName)){
			if(StringUtils.equals(contextPath, FORWARD_SLASH)){
				if(isEmbedded){
					applicationName = Paths.get(applicationDir).getFileName().toString();
				} else {
					applicationName = ROOT;
				}
			} else {
				applicationName = StringUtils.removeStart(StringUtils.replace(contextPath, FORWARD_SLASH, REPLACEMENT),
						REPLACEMENT);
				applicationName = StringUtils.removeEnd(applicationName, REPLACEMENT);
			}
		}

//		System.out.println("==========================================================================================");
//		System.out.println("Context details found : ");
//		System.out.println("Path : " + contextPath);
//		System.out.println("Major Version : " + majorServletVersion);
//		System.out.println("Minor Version : " + minorServletVersion);
//		System.out.println("Server Info : "+ serverInfo);
//		System.out.println("Application Dir : " +applicationDir );
//		System.out.println("Application Name : " + applicationName);
//		System.out.println("==========================================================================================");

		putContextInfo(contextPath, applicationDir, applicationName, serverPort);
//        System.out.println("Current servlet context map : " + ServletContextInfo.getInstance());
    }
}
