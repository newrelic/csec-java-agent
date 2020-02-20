package com.k2cybersecurity.instrumentator.utils;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;

import net.bytebuddy.description.type.TypeDescription;

public class AgentUtils {

	public Set<Pair<String, ClassLoader>> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<Pair<String, ClassLoader>> transformedClasses;

	private static AgentUtils instance;

	public Set<String> getProtectedVulnerabilties() {
		return protectedVulnerabilties;
	}

	private Set<String> protectedVulnerabilties = new HashSet<String>();

	private AgentUtils() {
		transformedClasses = new HashSet<>();
	}

	public static AgentUtils getInstance() {
		if (instance == null) {
			instance = new AgentUtils();
		}
		return instance;
	}

	public void clearTransformedClassSet() {
		transformedClasses.clear();
	}

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static void controlCommandProcessor(IntCodeControlCommand controlCommand) {
		switch (controlCommand.getControlCommand()) {
		case IntCodeControlCommand.CHANGE_LOG_LEVEL:
			if (controlCommand.getArguments().size() < 3)
				break;
			try {
				LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
				Integer duration = Integer.parseInt(controlCommand.getArguments().get(1));
				TimeUnit timeUnit = TimeUnit.valueOf(controlCommand.getArguments().get(2));
				LogWriter.updateLogLevel(logLevel, timeUnit, duration);
			} catch (Exception e) {
				logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e, AgentUtils.class.getSimpleName());
			}
			break;

		case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
			InstrumentationUtils.shutdownLogic(true);
			break;
		case IntCodeControlCommand.SET_DEFAULT_LOG_LEVEL:
			LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
			LogWriter.setLogLevel(logLevel);
			break;
		case IntCodeControlCommand.ENABLE_HTTP_REQUEST_PRINTING:
			K2Instrumentator.enableHTTPRequestPrinting = !K2Instrumentator.enableHTTPRequestPrinting;
			break;
		case IntCodeControlCommand.UPLOAD_LOGS:
			logger.log(LogLevel.INFO, "Is log file sent to IC: " + FtpClient.sendBootstrapLogFile(),
					AgentUtils.class.getSimpleName());
			break;
		case IntCodeControlCommand.UNSUPPORTED_AGENT:
			logger.log(LogLevel.SEVERE, controlCommand.getArguments().get(0), AgentUtils.class.getSimpleName());
			System.err.println(controlCommand.getArguments().get(0));
			HealthCheckScheduleThread.getInstance().shutDownThreadPoolExecutor();
			InstrumentationUtils.shutdownLogic(false);
			break;
		default:
			break;
		}
	}

	public void createProtectedVulnerabilties(TypeDescription typeDescription, ClassLoader classLoader) {
		String className = typeDescription.getName();
		System.out.println("Class Name : " + className);

		// NAME_BASED_HOOKS checks
		if (StringUtils.equals(className, "java.lang.ProcessImpl")) {
			getProtectedVulnerabilties().add("RCE");
			getProtectedVulnerabilties().add("RCI");
		} else if (StringUtils.equals(className, "java.lang.Shutdown")) {
			getProtectedVulnerabilties().add("RCI");
		} else if (StringUtils.equalsAny(className, "java.io.FileOutputStream", "java.io.FileInputStream",
				"sun.nio.fs.UnixNativeDispatcher", "java.io.UnixFileSystem", "java.io.RandomAccessFile",
				"java.io.FileSystem")) {
			getProtectedVulnerabilties().add("FILE_ACCESS");
			getProtectedVulnerabilties().add("RCI");
		} else if (StringUtils.startsWith(className, "com.mongodb.")) {
			getProtectedVulnerabilties().add("NOSQLI");
		} else if (StringUtils.equalsAny(className, "java.util.Random", "java.lang.Math")) {
			getProtectedVulnerabilties().add("WEAK_RANDOM");
		} else if (StringUtils.equalsAny(className, "org.apache.xpath.XPath",
				"com.sun.org.apache.xpath.internal.XPath")) {
			getProtectedVulnerabilties().add("XPATH");
		} else if (StringUtils.equalsAny(className, "org.apache.http.protocol.HttpRequestExecutor",
				"sun.net.www.protocol.http.Handler", "sun.net.www.protocol.https.Handler",
				"com.sun.net.ssl.internal.www.protocol.https.Handler", "jdk.incubator.http.MultiExchange",
				"org.apache.commons.httpclient.HttpMethodDirector", "com.squareup.okhttp.internal.http.HttpEngine",
				"weblogic.net.http.Handler")) {
			getProtectedVulnerabilties().add("SSRF");
		} else if (StringUtils.equalsAny(className, "javax.crypto.Cipher", "javax.crypto.KeyGenerator",
				"java.security.KeyPairGenerator")) {
			getProtectedVulnerabilties().add("CRYPTO");
		} else if (StringUtils.equals(className, "java.security.MessageDigest")) {
			getProtectedVulnerabilties().add("HASH");
		} else if (StringUtils.contains(className, "javax.servlet.ServletResponse")) {
			getProtectedVulnerabilties().add("RXSS");
		} else if (StringUtils.contains(className, "javax.servlet.http.HttpSession")) {
			getProtectedVulnerabilties().add("TRUST_BOUNDARY");
		} else if (StringUtils.contains(className, "javax.servlet.http.HttpServletResponse")) {
			getProtectedVulnerabilties().add("SECURE_COOKIE");
		} else {
			// TYPE_BASED_HOOKS checks
				try {
					if(StringUtils.equals("java.sql.Statement", className) || StringUtils.equals("java.sql.PreparedStatement", className) || StringUtils.equals("java.sql.Connection", className) || typeDescription.isInHierarchyWith(Class.forName("java.sql.Statement", false, classLoader)) || typeDescription.isInHierarchyWith(Class.forName("java.sql.PreparedStatement", false, classLoader)) || typeDescription.isInHierarchyWith(Class.forName("java.sql.Connection", false, classLoader))){
						getProtectedVulnerabilties().add("SQLI");
						getProtectedVulnerabilties().add("SXSS");
					} else if(StringUtils.equals("javax.naming.directory.DirContext", className) || typeDescription.isInHierarchyWith(Class.forName("javax.naming.directory.DirContext", false, classLoader))) {
						getProtectedVulnerabilties().add("LDAP");
					}
				} catch (ClassNotFoundException e) {
					logger.log(LogLevel.ERROR,
							"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(),
							AgentUtils.class.getSimpleName());
				}
			
		}

		System.out.println("getProtectedVulnerabilties : " + getProtectedVulnerabilties().toString());
	}
}
