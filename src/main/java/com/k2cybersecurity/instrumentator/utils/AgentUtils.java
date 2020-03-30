package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.IPBlockingEntry;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerableAPI;
import net.bytebuddy.description.type.TypeDescription;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class AgentUtils {

	public static final String IP_ADDRESS_UNBLOCKED_DUE_TO_TIMEOUT_S = "IP address unblocked due to timeout : %s";

	public Set<Pair<String, ClassLoader>> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<Pair<String, ClassLoader>> transformedClasses;

	private Map<String, EventResponse> eventResponseSet;

	private Map<String, VulnerableAPI> vulnerableAPIMap;

	private static AgentUtils instance;

	public Set<String> getProtectedVulnerabilties() {
		return protectedVulnerabilties;
	}

	private Set<String> protectedVulnerabilties = new HashSet<String>();

	private Set<DeployedApplication> scannedDeployedApplications = new HashSet<DeployedApplication>();

	public static long ipBlockingTimeout = TimeUnit.HOURS.toMillis(1);

	private static Map<String, IPBlockingEntry> ipBlockingEntries = new HashMap<>();

	private AgentUtils() {
		transformedClasses = new HashSet<>();
		eventResponseSet = new ConcurrentHashMap<>();
		vulnerableAPIMap = new ConcurrentHashMap<>();
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

	public Map<String, EventResponse> getEventResponseSet() {
		return eventResponseSet;
	}

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public Map<String, VulnerableAPI> getVulnerableAPIMap() {
		return vulnerableAPIMap;
	}

	public VulnerableAPI isVulnerableAPI(JavaAgentEventBean event){
		VulnerableAPI vulnerableAPI = new VulnerableAPI(event.getSourceMethod(),
				event.getUserFileName(),
				event.getUserMethodName(),
				event.getLineNumber()
				);
		return vulnerableAPIMap.get(vulnerableAPI.getId());
	}

	public void createProtectedVulnerabilties(TypeDescription typeDescription, ClassLoader classLoader) {
		String className = typeDescription.getName();
		// NAME_BASED_HOOKS checks
		if (StringUtils.equals(className, "java.lang.ProcessImpl")) {
			getProtectedVulnerabilties().add("RCE");
			getProtectedVulnerabilties().add("RCI");
			getProtectedVulnerabilties().add("REVERSE_SHELL");
		} else if (StringUtils.equals(className, "java.lang.Shutdown")) {
			getProtectedVulnerabilties().add("RCI");
		} else if (StringUtils.equalsAny(className, "java.io.FileOutputStream", "java.io.FileInputStream",
				"sun.nio.fs.UnixNativeDispatcher", "java.io.UnixFileSystem", "java.io.RandomAccessFile",
				"java.io.FileSystem")) {
			getProtectedVulnerabilties().add("FILE_ACCESS");
			getProtectedVulnerabilties().add("RCI");
		} else if (StringUtils.startsWith(className, "com.mongodb.")) {
			getProtectedVulnerabilties().add("NOSQLI");
			getProtectedVulnerabilties().add("RCI");
			getProtectedVulnerabilties().add("SXSS");
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
			getProtectedVulnerabilties().add("RCI");
		} else if (StringUtils.equalsAny(className, "javax.crypto.Cipher", "javax.crypto.KeyGenerator",
				"java.security.KeyPairGenerator")) {
			getProtectedVulnerabilties().add("CRYPTO");
		} else if (StringUtils.equals(className, "java.security.MessageDigest")) {
			getProtectedVulnerabilties().add("HASH");
		} else {
			// TYPE_BASED_HOOKS checks
			try {
				if(StringUtils.equals("java.sql.Statement", className) || StringUtils.equals("java.sql.PreparedStatement", className) || StringUtils.equals("java.sql.Connection", className) || typeDescription.isInHierarchyWith(Class.forName("java.sql.Statement", false, classLoader)) || typeDescription.isInHierarchyWith(Class.forName("java.sql.PreparedStatement", false, classLoader)) || typeDescription.isInHierarchyWith(Class.forName("java.sql.Connection", false, classLoader))){
					getProtectedVulnerabilties().add("SQLI");
					getProtectedVulnerabilties().add("SXSS");
					getProtectedVulnerabilties().add("RCI");
				} else if(StringUtils.equals("javax.naming.directory.DirContext", className) || typeDescription.isInHierarchyWith(Class.forName("javax.naming.directory.DirContext", false, classLoader))) {
					getProtectedVulnerabilties().add("LDAP");
				} else if (StringUtils.contains("javax.servlet.ServletResponse", className) || typeDescription.isInHierarchyWith(Class.forName("javax.servlet.ServletResponse", false, classLoader))) {
					getProtectedVulnerabilties().add("RXSS");
				} else if (StringUtils.contains("javax.servlet.http.HttpServletResponse", className) || typeDescription.isInHierarchyWith(Class.forName("javax.servlet.http.HttpServletResponse", false, classLoader))) {
					getProtectedVulnerabilties().add("SECURE_COOKIE");
				} else if (StringUtils.contains("javax.servlet.http.HttpSession", className) || typeDescription.isInHierarchyWith(Class.forName("javax.servlet.http.HttpSession", false, classLoader))) {
					getProtectedVulnerabilties().add("TRUST_BOUNDARY");
				}
			} catch (ClassNotFoundException e) {
				logger.log(LogLevel.ERROR,
						"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(),
						AgentUtils.class.getSimpleName());
			}
		}
	}

	public void addProtectedVulnerabilties(String className) {
		if (StringUtils.equalsAny(className,"com.sun.org.apache.xerces.internal.impl.XMLDocumentFragmentScannerImpl", "com.sun.org.apache.xerces.internal.impl.XMLEntityManager")) {
			getProtectedVulnerabilties().add("XXE");
		} else if (StringUtils.equals(className, "java.io.ObjectInputStream")) {
			getProtectedVulnerabilties().add("INSECURE_DESERIALIZATION");
		}
	}

	public Set<DeployedApplication> getScannedDeployedApplications() {
		return scannedDeployedApplications;
	}

	public void addScannedDeployedApplications(DeployedApplication scannedDeployedApplications) {
		if(scannedDeployedApplications != null && !scannedDeployedApplications.isEmpty()) {
			this.scannedDeployedApplications.add(scannedDeployedApplications);
		}
	}

	public void addIPBlockingEntry(String ip){
		IPBlockingEntry entry = new IPBlockingEntry(ip);
		ipBlockingEntries.put(entry.getTargetIP(), entry);
	}

	public boolean isBlockedIP(String ip){
		if(ipBlockingEntries.containsKey(ip)){
			if(!ipBlockingEntries.get(ip).isValid()){
				ipBlockingEntries.remove(ip);
				logger.log(LogLevel.INFO, String.format(IP_ADDRESS_UNBLOCKED_DUE_TO_TIMEOUT_S, ip), AgentUtils.class.getName());
				return false;
			} else {
				return true;
			}
		}
		return false;
	}

}
