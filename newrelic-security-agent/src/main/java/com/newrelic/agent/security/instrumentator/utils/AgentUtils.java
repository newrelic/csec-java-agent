package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.httpclient.IASTDataTransferRequestProcessor;
import com.newrelic.agent.security.intcodeagent.constants.AgentServices;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.DeployedApplication;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.config.AgentPolicyParameters;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ApplicationURLMappings;
import com.newrelic.agent.security.intcodeagent.models.javaagent.EventResponse;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.STARTED_MODULE_LOG;

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
    public static final String CAME_TO_EXTRACT_TAR_BUNDLE = "Came to extract tar bundle : ";
    public static final String ENFORCING_POLICY = "Enforcing policy";
    public static final String LOG_LEVEL_PROVIDED_IN_POLICY_IS_INCORRECT_DEFAULTING_TO_INFO = "Log level provided in policy is incorrect: %s. Staying at current level";
    public static final String ERROR_WHILE_EXTRACTING_FILE_FROM_ARCHIVE_S_S = "Error while extracting file from archive : %s : %s";
    public static final String OVER_RIDE_POLICY_DISABLED_IN_NR_CONFIG_AT_S = "Over-ride policy disabled in NR config at '%s'.";
    public static final String OVERRIDDEN = "overridden";
    public static final String NR_POLICY_OVER_RIDE_IN_PLACE_UPDATED_POLICY_S = "NR policy over-ride in place. Updated policy : %s";
    public static final String POLICY_VERSION = "policy-version";
    public static final String ERROR_WHILE_SENDING_UPDATED_POLICY_TO_REMOTE = "Error while sending updated policy to remote";
    public static final String ERROR_WHILE_SENDING_UPDATED_POLICY_TO_REMOTE_S_S = "Error while sending updated policy to remote : %s : %s";

    private Map<String, ClassLoader> classLoaderRecord;

    private Map<String, EventResponse> eventResponseSet;

    private Set<String> scannedAPIIds;

    private Set<String> rxssSentUrls;

    private Set<DeployedApplication> deployedApplicationUnderProcessing;

    private static AgentUtils instance;

    private static final Object lock = new Object();
    private Object mutex = new Object();

    public Set<String> getProtectedVulnerabilties() {
        return protectedVulnerabilties;
    }

    private Set<String> protectedVulnerabilties = new HashSet<String>();

    private Set<DeployedApplication> scannedDeployedApplications = new HashSet<DeployedApplication>();

    private Pattern TRACE_PATTERN;

//	private Map<Integer, JADatabaseMetaData> sqlConnectionMap;

    private AgentPolicy agentPolicy = new AgentPolicy();

    private AgentPolicy defaultAgentPolicy = new AgentPolicy();

    private AgentPolicyParameters agentPolicyParameters = new AgentPolicyParameters();

    private AtomicInteger outboundHttpConnectionId = new AtomicInteger(1000);

    private boolean collectAppInfoFromEnv = false;
    private Map<String, String> statusLogValues = new HashMap<>();

    private Collection<String> statusLogMostRecentHCs = new CircularFifoQueue<>(5);

    private Collection<String> statusLogMostRecentErrors = new CircularFifoQueue<>(5);

    private boolean isPolicyOverridden = false;

    private AgentUtils() {
        eventResponseSet = new ConcurrentHashMap<>();
        classLoaderRecord = new ConcurrentHashMap<>();
        scannedAPIIds = ConcurrentHashMap.newKeySet();
        rxssSentUrls = new HashSet<>();
        deployedApplicationUnderProcessing = new HashSet<>();
        TRACE_PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);

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

    public Map<String, ClassLoader> getClassLoaderRecord() {
        return classLoaderRecord;
    }

    public Map<String, EventResponse> getEventResponseSet() {
        return eventResponseSet;
    }

    public Set<String> getScannedAPIIds() {
        return scannedAPIIds;
    }

    public int incrementOutboundHttpConnectionId() {
        return this.outboundHttpConnectionId.getAndIncrement();
    }

    public void resetOutboundHttpConnectionId() {
        this.outboundHttpConnectionId.set(1000);
    }

    public boolean isCollectAppInfoFromEnv() {
        return collectAppInfoFromEnv;
    }

    public void setCollectAppInfoFromEnv(boolean collectAppInfoFromEnv) {
        this.collectAppInfoFromEnv = collectAppInfoFromEnv;
    }

    public AgentPolicyParameters getAgentPolicyParameters() {
        return agentPolicyParameters;
    }

    public void setAgentPolicyParameters(AgentPolicyParameters agentPolicyParameters) {
        this.agentPolicyParameters = agentPolicyParameters;
    }

    public boolean isPolicyOverridden() {
        return isPolicyOverridden;
    }

    public void setPolicyOverridden(boolean policyOverridden) {
        isPolicyOverridden = policyOverridden;
    }

    public Map<String, String> getStatusLogValues() {
        return statusLogValues;
    }

    public void setStatusLogValues(Map<String, String> statusLogValues) {
        this.statusLogValues = statusLogValues;
    }

    public boolean addStatusLogMostRecentHCs(String healthCheck) {
        synchronized (mutex) {
            return statusLogMostRecentHCs.add(healthCheck);
        }
    }

    public Collection<String> getStatusLogMostRecentHCs() {
        return statusLogMostRecentHCs;
    }

    public void setStatusLogMostRecentHCs(Collection<String> statusLogMostRecentHCs) {
        this.statusLogMostRecentHCs = statusLogMostRecentHCs;
    }

    public boolean addStatusLogMostRecentErrors(String error){
        synchronized (mutex) {
            return this.statusLogMostRecentErrors.add(error);
        }
    }

    public Collection<String> getStatusLogMostRecentErrors() {
        return statusLogMostRecentErrors;
    }

    public void setStatusLogMostRecentErrors(Collection<String> statusLogMostRecentErrors) {
        this.statusLogMostRecentErrors = statusLogMostRecentErrors;
    }

    public AgentPolicy getDefaultAgentPolicy() {
        return defaultAgentPolicy;
    }

    public void setDefaultAgentPolicy(AgentPolicy defaultAgentPolicy) {
        this.defaultAgentPolicy = defaultAgentPolicy;
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

    public String detectDeployedApplicationPath(String userClassName, Class<?> currentGenericServletInstance,
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
                                currentGenericServletInstance.getClassLoader());
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
                    Enumeration<URL> appPathURLEnum = classLoader.getResources(StringUtils.EMPTY);
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
            logger.log(LogLevel.SEVERE, ERROR, e, AgentUtils.class.getName());
        }
        return appPath;
    }

    public void putClassloaderRecord(String className, ClassLoader classLoader) {
        if (classLoader != null) {
            classLoaderRecord.put(className, classLoader);
        }
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

    public boolean applyPolicyOverrideIfApplicable() {
        AgentUtils.getInstance().applyNRPolicyOverride();
        if (AgentUtils.getInstance().isPolicyOverridden()) {
            AgentUtils.getInstance().getAgentPolicy().setVersion(OVERRIDDEN);
            logger.log(LogLevel.INFO, String.format(NR_POLICY_OVER_RIDE_IN_PLACE_UPDATED_POLICY_S,
                    JsonConverter.toJSON(AgentUtils.getInstance().getAgentPolicy())), AgentUtils.class.getName());
            try {
                WSClient.getInstance().send(JsonConverter.toJSON(AgentUtils.getInstance().getAgentPolicy()));
                AgentUtils.getInstance().getStatusLogValues().put(POLICY_VERSION, AgentUtils.getInstance().getAgentPolicy().getVersion());
                EventSendPool.getInstance().sendEvent(AgentInfo.getInstance().getApplicationInfo());
                return true;
            } catch (Throwable e) {
                logger.log(LogLevel.SEVERE, String.format(ERROR_WHILE_SENDING_UPDATED_POLICY_TO_REMOTE_S_S, e.getMessage(), e.getCause()), AgentUtils.class.getName());
                logger.log(LogLevel.FINER, ERROR_WHILE_SENDING_UPDATED_POLICY_TO_REMOTE, e, AgentUtils.class.getName());
            }
        }
        return false;
    }

    /**
     * On startup, Instantiating collector policy with default values.
     */
    public static void instantiateDefaultPolicy() {
        logger.log(LogLevel.FINE, "Instantiating collector policy with default!!!", AgentUtils.class.getName());
        applyPolicy(AgentUtils.getInstance().getDefaultAgentPolicy());
    }

    public static boolean applyPolicy(AgentPolicy newPolicy) {
        try {
            AgentUtils.getInstance().setAgentPolicy(newPolicy);
            AgentInfo.getInstance().getApplicationInfo().setPolicyVersion(AgentUtils.getInstance().getAgentPolicy().getVersion());
            logger.logInit(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_APPLIED_S,
                    JsonConverter.toJSON(AgentUtils.getInstance().getAgentPolicy())), AgentUtils.class.getName());
            AgentUtils.getInstance().getStatusLogValues().put(POLICY_VERSION, AgentUtils.getInstance().getAgentPolicy().getVersion());
            EventSendPool.getInstance().sendEvent(AgentInfo.getInstance().getApplicationInfo());

            return true;
        } catch (Throwable e) {
            logger.logInit(LogLevel.SEVERE, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR, e,
                    AgentUtils.class.getName());
            return false;
        }
    }

    private boolean isAppScanNeeded() {
        return !scannedDeployedApplications.containsAll(AgentInfo.getInstance().getApplicationInfo().getServerInfo().getDeployedApplications());
    }

    public static String stackTraceElementToString(StackTraceElement element) {
        StringBuilder builder = new StringBuilder(element.getClassName());
        builder.append(".");
        builder.append(element.getMethodName());
        if(element.isNativeMethod()) {
            builder.append("(Native Method)");
        } else {
            if(element.getFileName() != null && element.getLineNumber() >= 0){
                builder.append("(");
                builder.append(element.getFileName());
                builder.append(":");
                builder.append(element.getLineNumber());
                builder.append(")");
            } else {
                if(element.getFileName() != null) {
                    builder.append("(");
                    builder.append(element.getFileName());
                    builder.append(")");
                } else {
                    builder.append("(Unknown Source)");
                }
            }
        }
        
        return builder.toString();
    }

    public long getProcessID(Process p) {
        long result = -1;
        try {
            //for windows
            if (p.getClass().getName().equals("java.lang.Win32Process") ||
                    p.getClass().getName().equals("java.lang.ProcessImpl")) {
                Field f = p.getClass().getDeclaredField("handle");
                f.setAccessible(true);
                long handl = f.getLong(p);
                Kernel32 kernel = Kernel32.INSTANCE;
                WinNT.HANDLE hand = new WinNT.HANDLE();
                hand.setPointer(Pointer.createConstant(handl));
                result = kernel.GetProcessId(hand);
                f.setAccessible(false);
            }
            //for unix based operating systems
            else if (p.getClass().getName().equals("java.lang.UNIXProcess")) {
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

    public boolean unZipFile(File zipFile, File outputDir) {
        // Create zip file stream.
        try (ZipArchiveInputStream archive = new ZipArchiveInputStream(
                new BufferedInputStream(new FileInputStream(zipFile)))) {

            ZipArchiveEntry entry;
            while ((entry = archive.getNextZipEntry()) != null) {
                // Print values from entry.
                // ZipEntry.DEFLATED is int 8
                File file = new File(outputDir, entry.getName());
                if (entry.isDirectory()) {
                    file.mkdirs();
                } else {
                    // Stream file content
                    IOUtils.copy(archive, new FileOutputStream(file));
                }
            }
            return true;
        } catch (IOException e) {
            logger.log(LogLevel.SEVERE, "Error : ", e, AgentUtils.class.getName());
        }
        return false;
    }

    public static Set<PosixFilePermission> intToPosixFilePermission(int mode) {
        if (mode >= 1000 || mode < 0) {
            throw new IllegalArgumentException("Invalid mode " + mode);
        }

        final int owner = mode / 100;
        final int group = (mode - owner * 100) / 10;
        final int others = mode - owner * 100 - group * 10;

        if (owner > 7 || group > 7 || others > 7) {
            throw new IllegalArgumentException("Invalid mode " + mode);
        }

        Set<PosixFilePermission> posixFilePermissionSet = new HashSet<>();
        posixFilePermissionSet.addAll(singleIntToFilePermission(owner, "OWNER"));
        posixFilePermissionSet.addAll(singleIntToFilePermission(owner, "GROUP"));
        posixFilePermissionSet.addAll(singleIntToFilePermission(owner, "OTHERS"));
        return posixFilePermissionSet;
    }

    private static Set<PosixFilePermission> singleIntToFilePermission(Integer mode, String groupType) {
        Set<PosixFilePermission> permissions = new HashSet<>(9);

        if (Arrays.asList(new Integer[]{1, 3, 5, 7}).contains(mode)) {
            permissions.add(PosixFilePermission.valueOf(groupType + "_EXECUTE"));
        }

        if (Arrays.asList(new Integer[]{2, 3, 6, 7}).contains(mode)) {
            permissions.add(PosixFilePermission.valueOf(groupType + "_WRITE"));
        }

        if (Arrays.asList(new Integer[]{4, 5, 6, 7}).contains(mode)) {
            permissions.add(PosixFilePermission.valueOf(groupType + "_READ"));
        }

        return permissions;
    }

    public static Set<PosixFilePermission> octToPosixFilePermission(int modeOct) {
        // TODO: optimize this method and make it cleaner
        int modeInt = Integer.parseInt(Integer.toString(modeOct, 8));

        return intToPosixFilePermission(modeInt);
    }

    /*
        Apply any applicable NR policy over-rides
        TODO: in long term we shall look into alternate approaches to set these over-rides
                since the current one is an exhaustive book-keeping.
     */
    private void applyNRPolicyOverride() {
        boolean override = false;
        if (!NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_ENFORCE, false)) {
            logger.log(LogLevel.FINER, String.format(OVER_RIDE_POLICY_DISABLED_IN_NR_CONFIG_AT_S, INRSettingsKey.SECURITY_POLICY_ENFORCE), AgentUtils.class.getName());
            this.setPolicyOverridden(override);
            return;
        }
        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_ENABLE) != null) {
            this.getAgentPolicy().getVulnerabilityScan().setEnabled(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_ENABLE));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_ENABLE) != null) {
            this.getAgentPolicy().getVulnerabilityScan().getIastScan().setEnabled(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_ENABLE));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_INTERVAL) != null){
            this.getAgentPolicy().getVulnerabilityScan().getIastScan().getProbing().setInterval(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_INTERVAL));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_BATCH_SIZE) != null){
            this.getAgentPolicy().getVulnerabilityScan().getIastScan().getProbing().setBatchSize(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_BATCH_SIZE));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_ENABLE) != null){
            this.getAgentPolicy().getProtectionMode().setEnabled(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_ENABLE));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ENABLE) != null){
            this.getAgentPolicy().getProtectionMode().getIpBlocking().setEnabled(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ENABLE));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ATTACKER_IP_BLOCKING) != null){
            this.getAgentPolicy().getProtectionMode().getIpBlocking().setAttackerIpBlocking(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ATTACKER_IP_BLOCKING));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_IP_DETECT_VIA_XFF) != null){
            this.getAgentPolicy().getProtectionMode().getIpBlocking().setIpDetectViaXFF(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_IP_DETECT_VIA_XFF));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_ENABLE) != null){
            this.getAgentPolicy().getProtectionMode().getApiBlocking().setEnabled(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_ENABLE));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ALL_APIS) != null){
            this.getAgentPolicy().getProtectionMode().getApiBlocking().setProtectAllApis(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ALL_APIS));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_KNOWN_VULNERABLE_APIS) != null){
            this.getAgentPolicy().getProtectionMode().getApiBlocking().setProtectKnownVulnerableApis(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_KNOWN_VULNERABLE_APIS));
            override = true;
        }

        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ATTACKED_APIS) != null){
            this.getAgentPolicy().getProtectionMode().getApiBlocking().setProtectAttackedApis(NewRelic.getAgent().getConfig().getValue(
                    INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ATTACKED_APIS));
            override = true;
        }

        this.setPolicyOverridden(override);
    }


    public static void sendApplicationURLMappings() {
        if (!WSUtils.isConnected()){
            NewRelicSecurity.getAgent().reportURLMapping();
            return;
        }
        ApplicationURLMappings applicationURLMappings = new ApplicationURLMappings(URLMappingsHelper.getApplicationURLMappings());
        applicationURLMappings.setApplicationUUID(AgentInfo.getInstance().getApplicationUUID());
        logger.logInit(LogLevel.INFO, String.format("Collected application url mappings %s", applicationURLMappings), Agent.class.getName());
        EventSendPool.getInstance().sendEvent(applicationURLMappings);
    }
}
