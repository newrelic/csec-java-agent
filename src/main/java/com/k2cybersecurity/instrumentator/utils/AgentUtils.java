package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.custom.ClassloaderAdjustments;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicyIPBlockingParameters;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import net.bytebuddy.description.type.TypeDescription;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.COM_SUN;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.SUN_REFLECT;

public class AgentUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static final String IP_ADDRESS_UNBLOCKED_DUE_TO_TIMEOUT_S = "IP address unblocked due to timeout : %s";
    public static final String CLASSES_STR = "/classes/";
    public static final String CLASSES_STR_1 = "/classes!";
    public static final String CLASSES_STR_2 = "/classes";
    public static final String NON_VULNERABLE_API_ALLOWED_TO_EXECUTE_S = "Non vulnerable API allowed to execute : %s";
    public static final String VULNERABLE_API_BLOCKED = "Vulnerable API blocked from execution : %s";
    public static final String CURRENT_GENERIC_SERVLET_INSTANCE_NULL_IN_DETECT_DEPLOYED_APPLICATION_PATH = "currentGenericServletInstance null in detectDeployedApplicationPath";
    public static final String PROTECTION_DOMAIN = "Protection domain : ";
    public static final String VFS = "vfs";
    public static final String ORG_JBOSS_VFS_VIRTUAL_FILE = "org.jboss.vfs.VirtualFile";
    public static final String GET_PHYSICAL_FILE = "getPhysicalFile";
    public static final String JBOSS_PROTECTION_DOMAIN = "Jboss Protection domain : ";
    public static final String CLASS_DIR_NOT_FOUND_IN_JBOSS_PROTECTION_DOMAIN = "Class dir not found in Jboss protection domain : ";
    public static final String JSP = "_jsp";
    public static final String START_URL_LISTING = "Start URL listing";
    public static final String L_1 = "L1 : ";
    public static final String CLASSLOADER_IS_NULL_IN_DETECT_DEPLOYED_APPLICATION_PATH = "Classloader is null in detectDeployedApplicationPath";
    public static final String ERROR = "Error :";
    public static final String CLASSLOADER_RECORD_MISSING_FOR_CLASS = "Classloader record missing for class : ";
    private static final String TWO_PIPES = "||";

    public Set<Pair<String, ClassLoader>> getTransformedClasses() {
        return transformedClasses;
    }

    private Set<Pair<String, ClassLoader>> transformedClasses;

    private Map<String, ClassLoader> classLoaderRecord;

    private Map<String, EventResponse> eventResponseSet;

    private Set<String> rxssSentUrls;

    private Set<DeployedApplication> deployedApplicationUnderProcessing;

	private static AgentUtils instance;

	private static final Object lock = new Object();

	public Set<String> getProtectedVulnerabilties() {
		return protectedVulnerabilties;
	}

	private Set<String> protectedVulnerabilties = new HashSet<String>();

	private Set<DeployedApplication> scannedDeployedApplications = new HashSet<DeployedApplication>();

	private Pattern TRACE_PATTERN;

	private Map<Integer, JADatabaseMetaData> sqlConnectionMap;

	private AgentPolicy agentPolicy;

	private AgentPolicyIPBlockingParameters agentPolicyParameters;

	private boolean isAgentActive = true;

	private CollectorInitMsg initMsg = null;

	private boolean cveEnvScanCompleted = false;

	private AgentUtils() {

		transformedClasses = new HashSet<>();
		eventResponseSet = new ConcurrentHashMap<>();
		classLoaderRecord = new ConcurrentHashMap<>();
		rxssSentUrls = new HashSet<>();
		deployedApplicationUnderProcessing = new HashSet<>();
		TRACE_PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
		this.sqlConnectionMap = new LinkedHashMap<Integer, JADatabaseMetaData>(50, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<Integer, JADatabaseMetaData> eldest) {
                return size() > 50;
            }
        };

	}

	public static AgentUtils getInstance() {
		if (instance == null) {
			synchronized (lock) {
				if (instance == null) {
					instance = new AgentUtils();
				}
			}
		}
		return instance;
	}

	public boolean isCveEnvScanCompleted() {
		return cveEnvScanCompleted;
	}

	public void setCveEnvScanCompleted(boolean cveEnvScanCompleted) {
		this.cveEnvScanCompleted = cveEnvScanCompleted;
	}

	public boolean isAgentActive() {
		return isAgentActive;
	}

	public void setAgentActive(boolean agentActive) {
		isAgentActive = agentActive;
	}

	public Map<Integer, JADatabaseMetaData> getSqlConnectionMap() {
		return sqlConnectionMap;
	}

	public Map<String, ClassLoader> getClassLoaderRecord() {
		return classLoaderRecord;
	}

	public void clearTransformedClassSet() {
		transformedClasses.clear();
	}

	public Map<String, EventResponse> getEventResponseSet() {
		return eventResponseSet;
	}

	public CollectorInitMsg getInitMsg() {
		return initMsg;
	}

	public void setInitMsg(CollectorInitMsg initMsg) {
		this.initMsg = initMsg;
	}

	public void createProtectedVulnerabilties(TypeDescription typeDescription, ClassLoader classLoader) {
		try {
			String className = typeDescription.getName();
			// NAME_BASED_HOOKS checks
			if (StringUtils.equals(className, "java.lang.ProcessImpl")) {
				getProtectedVulnerabilties().add("RCE");
				getProtectedVulnerabilties().add("RCI");
				getProtectedVulnerabilties().add("REVERSE_SHELL");
			} else if (StringUtils.equals(className, "java.lang.Shutdown")) {
				getProtectedVulnerabilties().add("RCI");
			} else if (StringUtils.equalsAny(className, "java.io.FileOutputStream", "java.io.FileInputStream",
					"sun.nio.fs.UnixNativeAgentUtils", "java.io.UnixFileSystem", "java.io.RandomAccessFile",
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
				boolean isFound = false;
				try {
					Class sqlStatement = null;
					Class sqlPreStatement = null;
					Class sqlConnection = null;

					if(classLoaderRecord.containsKey("java.sql.Statement")){
						sqlStatement = classLoaderRecord.get("java.sql.Statement").loadClass("java.sql.Statement");
					}

					if(classLoaderRecord.containsKey("java.sql.PreparedStatement")){
						sqlPreStatement = classLoaderRecord.get("java.sql.PreparedStatement").loadClass("java.sql.PreparedStatement");
					}

					if(classLoaderRecord.containsKey("java.sql.Connection")){
						sqlConnection = classLoaderRecord.get("java.sql.Connection").loadClass("java.sql.Connection");
					}

					if (!isFound && StringUtils.equals("java.sql.Statement", className)
							|| StringUtils.equals("java.sql.PreparedStatement", className)
							|| StringUtils.equals("java.sql.Connection", className)
							|| (sqlStatement !=null && typeDescription.isInHierarchyWith(sqlStatement))
							|| (sqlConnection !=null && typeDescription.isInHierarchyWith(sqlConnection))
							|| (sqlPreStatement !=null && typeDescription.isInHierarchyWith(sqlPreStatement))) {
						getProtectedVulnerabilties().add("SQLI");
						getProtectedVulnerabilties().add("SXSS");
						getProtectedVulnerabilties().add("RCI");
						isFound = true;
					}
				} catch (Throwable e) {
					logger.log(LogLevel.DEBUG,
							"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(), e,
							AgentUtils.class.getSimpleName());
				}
				try {

					Class dirContext = null;
					if(classLoaderRecord.containsKey("javax.naming.directory.DirContext")){
						dirContext = classLoaderRecord.get("javax.naming.directory.DirContext").loadClass("javax.naming.directory.DirContext");
					}


					if (!isFound && StringUtils.equals("javax.naming.directory.DirContext", className) ||
							(dirContext !=null && typeDescription.isInHierarchyWith(dirContext))) {
						getProtectedVulnerabilties().add("LDAP");
						isFound = true;
					}
				} catch (Throwable e) {
					logger.log(LogLevel.DEBUG,
							"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(), e,
							AgentUtils.class.getSimpleName());
				}


				try {
					Class servletResponse = null;
					if(classLoaderRecord.containsKey("javax.servlet.ServletResponse")){
						servletResponse = classLoaderRecord.get("javax.servlet.ServletResponse").loadClass("javax.servlet.ServletResponse");
					}

					if (!isFound && StringUtils.contains("javax.servlet.ServletResponse", className) ||
							(servletResponse !=null && typeDescription.isInHierarchyWith(servletResponse))) {
						getProtectedVulnerabilties().add("RXSS");
						isFound = true;
					}
				} catch (Throwable e) {
					logger.log(LogLevel.DEBUG,
							"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(), e,
							AgentUtils.class.getSimpleName());
				}


				try {
					Class httpServletResponse = null;
					if(classLoaderRecord.containsKey("javax.servlet.http.HttpServletResponse")){
						httpServletResponse = classLoaderRecord.get("javax.servlet.http.HttpServletResponse")
								.loadClass("javax.servlet.http.HttpServletResponse");
					}

					if (!isFound && StringUtils.contains("javax.servlet.http.HttpServletResponse", className)
							|| (httpServletResponse !=null && typeDescription.isInHierarchyWith(httpServletResponse))) {
						getProtectedVulnerabilties().add("SECURE_COOKIE");
						isFound = true;
					}
				} catch (Throwable e) {
					logger.log(LogLevel.DEBUG,
							"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(), e,
							AgentUtils.class.getSimpleName());
				}
				try {
					Class httpSession = null;
					if(classLoaderRecord.containsKey("javax.servlet.http.HttpSession")){
						httpSession = classLoaderRecord.get("javax.servlet.http.HttpSession")
								.loadClass("javax.servlet.http.HttpSession");
					}

					if (!isFound && StringUtils.contains("javax.servlet.http.HttpSession", className) ||
							(httpSession !=null && typeDescription.isInHierarchyWith(httpSession))) {
						getProtectedVulnerabilties().add("TRUST_BOUNDARY");
						isFound = true;
					}
				} catch (Throwable e) {
					logger.log(LogLevel.DEBUG,
							"Error in class loading for createProtectedVulnerabilties : " + e.getMessage(), e,
							AgentUtils.class.getSimpleName());
				}

			}
		} catch (Throwable e){
			logger.log(LogLevel.DEBUG,
					"Error in class loading for createProtectedVulnerabilties master: " + e.getMessage(), e,
					AgentUtils.class.getSimpleName());
		}
	}

	public void addProtectedVulnerabilties(String className) {
		if (StringUtils.equalsAny(className, "com.sun.org.apache.xerces.internal.impl.XMLDocumentFragmentScannerImpl",
				"com.sun.org.apache.xerces.internal.impl.XMLEntityManager")) {
			getProtectedVulnerabilties().add("XXE");
		} else if (StringUtils.equals(className, "java.io.ObjectInputStream")) {
			getProtectedVulnerabilties().add("INSECURE_DESERIALIZATION");
		}
	}

	public Set<DeployedApplication> getScannedDeployedApplications() {
		return scannedDeployedApplications;
	}

	public void addScannedDeployedApplications(DeployedApplication scannedDeployedApplications) {
		if (scannedDeployedApplications != null && !scannedDeployedApplications.isEmpty()) {
			this.scannedDeployedApplications.add(scannedDeployedApplications);
		}
	}

	public UserClassEntity detectUserClass(StackTraceElement[] trace, Object currentGenericServletInstance,
			String currentGenericServletMethodName, String fakeClassName, String fakeMethodName) {

		StackTraceElement userClass = null;
		int currentClassLoc = -1;

		UserClassEntity userClassEntity = new UserClassEntity();

		Set<String> superClasses = new HashSet<>();
//		logger.log(LogLevel.INFO, "Trace: " + Arrays.asList(trace),
//				AgentUtils.class.getName());
		if (currentGenericServletInstance != null) {
			Class currClass = currentGenericServletInstance.getClass();
			superClasses.add(currClass.getName());
			while (currClass.getSuperclass() != null) {
				currClass = currClass.getSuperclass();
				superClasses.add(currClass.getName());
			}
			if (!superClasses.isEmpty()) {
//				logger.log(LogLevel.INFO, "Detecting user class : " + superClasses + " : " + Arrays.asList(trace),
//						AgentUtils.class.getName());
				for (currentClassLoc = 0; currentClassLoc < trace.length; currentClassLoc++) {
					if (StringUtils.equals(trace[currentClassLoc].getMethodName(), currentGenericServletMethodName)
							&& StringUtils.equalsAny(trace[currentClassLoc].getClassName(),
									superClasses.toArray(new String[0]))) {
//						logger.log(LogLevel.INFO, "Process trace : " + trace[currentClassLoc],
//								AgentUtils.class.getName());
						userClass = trace[currentClassLoc];
						break;
					}
				}
			}
		}
		if (userClass == null) {
			return getFakeUserClass(trace, fakeClassName, fakeMethodName);
		}

		String packageName = StringUtils.EMPTY;
		Matcher matcher = TRACE_PATTERN.matcher(userClass.getClassName());
		if (!matcher.matches()) {
//			logger.log(LogLevel.INFO, "Not matched : " + userClass, AgentUtils.class.getName());
			userClassEntity.setCalledByUserCode(true);
			userClassEntity.setTraceLocationEnd(currentClassLoc);
			userClassEntity.setUserClassElement(userClass);
			return userClassEntity;
		} else {
			packageName = matcher.group();
			for (int i = currentClassLoc - 1; i >= 0; i--) {
				Matcher m1 = TRACE_PATTERN.matcher(trace[i].getClassName());
				if (!StringUtils.startsWith(trace[i].getClassName(), packageName) && !m1.matches()) {
					userClass = trace[i];
//					logger.log(LogLevel.INFO, "else finding : " + userClass, AgentUtils.class.getName());
					userClassEntity.setCalledByUserCode(true);
					userClassEntity.setTraceLocationEnd(i);
					userClassEntity.setUserClassElement(userClass);
					return userClassEntity;
				} else if (m1.matches()) {
					packageName = m1.group();
				}
			}
		}
		userClassEntity.setCalledByUserCode(false);
		userClassEntity.setTraceLocationEnd(currentClassLoc);
		userClassEntity.setUserClassElement(userClass);
		return userClassEntity;
	}

	private UserClassEntity getFakeUserClass(StackTraceElement[] trace, String fakeClassName, String fakeMethodName) {
		UserClassEntity userClassEntity = new UserClassEntity();
		userClassEntity.setCalledByUserCode(false);
		int loc = 0;
		boolean detect = false;
		for (loc = 0; loc < trace.length; loc++) {
			if (!detect && StringUtils.equals(fakeMethodName, trace[loc].getMethodName())
					&& StringUtils.equals(fakeClassName, trace[loc].getClassName())) {
				detect = true;
			} else if (detect && !IAgentConstants.TRACE_SKIP_REGEX.matcher(trace[loc].getClassName()).matches()) {
				userClassEntity.setUserClassElement(trace[loc]);
				userClassEntity.setTraceLocationEnd(loc);
				break;
			}
		}
		return userClassEntity;
	}

	public String detectDeployedApplicationPath(String userClassName, Object currentGenericServletInstance,
			String methodName) {
		String appPath = StringUtils.EMPTY;
		try {
			Class cls = null;
			if (currentGenericServletInstance != null) {

				boolean uncleanExit = false;
				if (classLoaderRecord.containsKey(userClassName)) {
					ClassLoader loader = classLoaderRecord.get(userClassName);
					try {
						if (loader != null) {
							cls = loader.loadClass(userClassName);
						} else {
							cls = Class.forName(userClassName, false, loader);
						}
					} catch (ClassNotFoundException e) {
						uncleanExit = true;
					}
				} else {
					uncleanExit = true;
				}

				if (uncleanExit) {
					logger.log(LogLevel.WARNING, CLASSLOADER_RECORD_MISSING_FOR_CLASS + userClassName,
							AgentUtils.class.getName());
					try {
						cls = Class.forName(userClassName, false,
								currentGenericServletInstance.getClass().getClassLoader());
					} catch (ClassNotFoundException e) {
						cls = Class.forName(userClassName, false, null);
					}
				}
			} else {
				logger.log(LogLevel.WARNING, CURRENT_GENERIC_SERVLET_INSTANCE_NULL_IN_DETECT_DEPLOYED_APPLICATION_PATH,
						AgentUtils.class.getName());
				return appPath;
			}

			URL protectionDomainLocation = cls.getProtectionDomain().getCodeSource().getLocation();

			logger.log(LogLevel.INFO, PROTECTION_DOMAIN + protectionDomainLocation, AgentUtils.class.getName());
			if (protectionDomainLocation != null) {
				if (StringUtils.equalsIgnoreCase(VFS, protectionDomainLocation.getProtocol())) {
					Class virtualFile = Class.forName(ORG_JBOSS_VFS_VIRTUAL_FILE, false, cls.getClassLoader());
					if (virtualFile.isInstance(protectionDomainLocation.getContent())) {
						Method getPhysicalFile = virtualFile.getMethod(GET_PHYSICAL_FILE);
						getPhysicalFile.setAccessible(true);
						File fileSystemFile = (File) getPhysicalFile.invoke(protectionDomainLocation.getContent());
						if (fileSystemFile != null && fileSystemFile.exists()) {
							appPath = fileSystemFile.getAbsolutePath();
							logger.log(LogLevel.INFO, JBOSS_PROTECTION_DOMAIN + fileSystemFile,
									AgentUtils.class.getName());
						}
					} else {
						logger.log(LogLevel.WARNING,
								CLASS_DIR_NOT_FOUND_IN_JBOSS_PROTECTION_DOMAIN + protectionDomainLocation.getContent(),
								AgentUtils.class.getName());
					}
				} else {
					appPath = protectionDomainLocation.getPath();
				}
			}

			if (StringUtils.isBlank(appPath)
					|| (StringUtils.endsWith(userClassName, JSP) && StringUtils.startsWith(methodName, JSP))) {
				appPath = StringUtils.EMPTY;
				ClassLoader classLoader = cls.getClassLoader();
				if (classLoader != null) {
                    logger.log(LogLevel.INFO, START_URL_LISTING, AgentUtils.class.getName());
                    Enumeration<java.net.URL> appPathURLEnum = classLoader.getResources(StringUtils.EMPTY);
                    while (appPathURLEnum != null && appPathURLEnum.hasMoreElements()) {
                        URL app = appPathURLEnum.nextElement();
                        logger.log(LogLevel.INFO, L_1 + app, AgentUtils.class.getName());
                        if (StringUtils.equalsIgnoreCase(VFS, app.getProtocol())) {
                            Class virtualFile = Class.forName(ORG_JBOSS_VFS_VIRTUAL_FILE, false, cls.getClassLoader());
                            if (virtualFile.isInstance(app.getContent())) {
                                Method getPhysicalFile = virtualFile.getMethod(GET_PHYSICAL_FILE);
                                getPhysicalFile.setAccessible(true);
                                File fileSystemFile = (File) getPhysicalFile.invoke(app.getContent());
                                if (fileSystemFile != null && fileSystemFile.exists()) {
                                    appPath = fileSystemFile.getAbsolutePath();
                                    logger.log(LogLevel.INFO, JBOSS_PROTECTION_DOMAIN + fileSystemFile,
                                            AgentUtils.class.getName());
                                }
                            } else {
                                logger.log(LogLevel.WARNING, CLASS_DIR_NOT_FOUND_IN_JBOSS_PROTECTION_DOMAIN + app.getContent(), AgentUtils.class.getName());
                            }
                        } else {
                            appPath = app.getPath();
                        }
                        if (StringUtils.containsAny(appPath, CLASSES_STR, CLASSES_STR_1) || StringUtils.endsWith(appPath, CLASSES_STR_2)) {
                            break;
                        } else {
                            appPath = StringUtils.EMPTY;
                        }
                    }
                } else {
					logger.log(LogLevel.WARNING, CLASSLOADER_IS_NULL_IN_DETECT_DEPLOYED_APPLICATION_PATH,
							AgentUtils.class.getName());
				}
			}
		} catch (Throwable e) {
			logger.log(LogLevel.ERROR, ERROR, e, AgentUtils.class.getName());
        }
        return appPath;
    }

    public void putClassloaderRecord(String className, ClassLoader classLoader) {
        if (classLoader != null) {
            classLoaderRecord.put(className, classLoader);
        }
    }

    public String getSHA256HexDigest(List<String> data) {
        data.removeAll(Collections.singletonList(null));
        String input = StringUtils.joinWith(TWO_PIPES, data);
        return DigestUtils.sha256Hex(input);
    }

    /**
     * @return the rxssSentUrls
     */
    public Set<String> getRxssSentUrls() {
        return rxssSentUrls;
    }


    public Set<DeployedApplication> getDeployedApplicationUnderProcessing() {
        return deployedApplicationUnderProcessing;
    }

    public AgentPolicy getAgentPolicy() {
        return agentPolicy;
    }

    public void setAgentPolicy(AgentPolicy agentPolicy) {
        this.agentPolicy = agentPolicy;
    }

    public AgentPolicyIPBlockingParameters getAgentPolicyParameters() {
        return agentPolicyParameters;
    }

    public void setAgentPolicyParameters(AgentPolicyIPBlockingParameters agentPolicyParameters) {
        this.agentPolicyParameters = agentPolicyParameters;
    }

    public void enforcePolicy() {
		if(AgentUtils.getInstance().getAgentPolicy().getIastMode().getEnabled() && AgentUtils.getInstance().getAgentPolicy().getIastMode().getStaticScanning().getEnabled() && !AgentUtils.getInstance().isCveEnvScanCompleted()){
			//Run CVE scan on ENV
			Pair<String, String> kindId = CommonUtils.getKindIdPair(K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier(), AgentUtils.getInstance().getInitMsg().getAgentInfo().getNodeId());
			CVEScannerPool.getInstance().dispatchScanner(AgentUtils.getInstance().getInitMsg().getAgentInfo().getNodeId(), kindId.getKey(), kindId.getValue(), false, true);
			AgentUtils.getInstance().setCveEnvScanCompleted(true);
		}
    }

    public void enforcePolicyParameters() {
    }

    public void
    preProcessStackTrace(AbstractOperationalBean operationalBean, VulnerabilityCaseType vulnerabilityCaseType) {
        StackTraceElement[] stackTrace = operationalBean.getStackTrace();
        int resetFactor = 0;
        List<StackTraceElement> recordsToDelete = new ArrayList<>();

        List<StackTraceElement> newTraceForIdCalc = new ArrayList<>();
        List<String> newTraceStringForIdCalc = new ArrayList<>();

        newTraceForIdCalc.addAll(Arrays.asList(stackTrace));

        recordsToDelete.add(stackTrace[0]);
        resetFactor++;
        for (int i = 1; i < stackTrace.length; i++) {
            if (i < operationalBean.getUserClassEntity().getTraceLocationEnd() && i == resetFactor &&
                    StringUtils.startsWith(stackTrace[i].getClassName(), ClassloaderAdjustments.K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
                recordsToDelete.add(stackTrace[i]);
                resetFactor++;
            }

            if (StringUtils.startsWithAny(stackTrace[i].getClassName(), SUN_REFLECT, COM_SUN)
                    || stackTrace[i].isNativeMethod() || stackTrace[i].getLineNumber() < 0) {
                recordsToDelete.add(stackTrace[i]);
            }
        }
		newTraceForIdCalc.removeAll(recordsToDelete);
		newTraceForIdCalc.forEach(stackTraceElement -> {
			newTraceStringForIdCalc.add(stackTraceElement.toString());
		});
		stackTrace = Arrays.copyOfRange(stackTrace, resetFactor, stackTrace.length);
		operationalBean.setStackTrace(stackTrace);
		operationalBean.getUserClassEntity().setTraceLocationEnd(operationalBean.getUserClassEntity().getTraceLocationEnd() - resetFactor);
		setAPIId(operationalBean, newTraceStringForIdCalc, vulnerabilityCaseType);
	}

	private void setAPIId(AbstractOperationalBean operationalBean, List<String> traceForIdCalc, VulnerabilityCaseType vulnerabilityCaseType) {
		List<String> idData = new ArrayList<>();

		// TODO : Write Application detection mechanism for a given event.
		idData.add(StringUtils.EMPTY);
		idData.addAll(traceForIdCalc);
		idData.add(vulnerabilityCaseType.getCaseType());
		operationalBean.setApiID(AgentUtils.getInstance().getSHA256HexDigest(idData));
	}

	public long getProcessID(Process p) {
		long result = -1;
		try {
			//for windows
//			if (p.getClass().getName().equals("java.lang.Win32Process") ||
//					p.getClass().getName().equals("java.lang.ProcessImpl"))
//			{
//				Field f = p.getClass().getDeclaredField("handle");
//				f.setAccessible(true);
//				long handl = f.getLong(p);
//				Kernel32 kernel = Kernel32.INSTANCE;
//				WinNT.HANDLE hand = new WinNT.HANDLE();
//				hand.setPointer(Pointer.createConstant(handl));
//				result = kernel.GetProcessId(hand);
//				f.setAccessible(false);
//			}
//			else
			//for unix based operating systems

			if (p.getClass().getName().equals("java.lang.UNIXProcess")) {
				Field f = p.getClass().getDeclaredField("pid");
				f.setAccessible(true);
				result = f.getLong(p);
				f.setAccessible(false);
			}
		} catch (Exception ex) {
			result = -1;
		}
		return result;
	}

	public void killProcessTree(long pid) {
//    	Runtime.getRuntime().exec()
	}
}
