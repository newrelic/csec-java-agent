package com.k2cybersecurity.instrumentator;

import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.*;
import com.k2cybersecurity.intcodeagent.constants.AgentServices;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.PolicyApplicationInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.properties.K2JAVersionInfo;
import com.k2cybersecurity.intcodeagent.schedulers.GlobalPolicyParameterPullST;
import com.k2cybersecurity.intcodeagent.schedulers.PolicyPullST;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import oshi.SystemInfo;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.URI;
import java.net.URL;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

/**
 * Utility entry point for K2 services
 */
public class K2Instrumentator {

    private static final String APP_INFO_GATHERING_FINISHED = "[APP_INFO] Application info generated : %s.";
    private static final String APP_INFO_GATHERING_STARTED = "[STEP-3][BEGIN][APP_INFO] Gathering application info for current process.";
    private static final String APP_INFO_BEAN_NOT_CREATED = "[APP_INFO] Error K2 application info bean not created.";
    private static final String AGENT_INIT_SUCCESSFUL = "[STEP-2][PROTECTION][COMPLETE] Protecting new process with PID %s and UUID %s : %s.";

    private static final String INIT_STARTED_AGENT_ATTACHED = "[STEP-2][PROTECTION][BEGIN] K2 Java collector attached to process: PID = %s, with generated applicationUID = %s by %s attachment";
    public static final String DEFAULT_GROUP_NAME = "IAST";

    public static Integer VMPID;
    public static final String APPLICATION_UUID = UUID.randomUUID().toString();
    public static ApplicationInfoBean APPLICATION_INFO_BEAN;
    public static JAHealthCheck JA_HEALTH_CHECK;
    public static String K2_HOME;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static boolean isDynamicAttach = false;

    private static OSVariables osVariables;

    static {
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            String runningVM = runtimeMXBean.getName();
            VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
        } catch (Throwable th) {
            logger.log(LogLevel.ERROR, ERROR_WHILE_INITIALISING_THE_K2_AGENT + th.getCause() + " : " + th.getMessage(), K2Instrumentator.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR, ERROR_WHILE_INITIALISING_THE_K2_AGENT + th.getCause() + " : " + th.getMessage(), th, K2Instrumentator.class.getName());
        }
    }

    /**
     * In continuation of premain, this will initialise all required K2 service and register application to K2 int code.
     *
     * @param isDynamicAttach true, if k2 agent is attached dynamically.
     * @return
     */
    public static boolean init(Boolean isDynamicAttach) {
        try {
            K2Instrumentator.isDynamicAttach = isDynamicAttach;
            String attachmentType = isDynamicAttach ? DYNAMIC : STATIC;

            osVariables = OsVariablesInstance.getInstance().getOsVariables();

            EnvLogUtils.logK2Env();

            // log init
            logger.logInit(
                    LogLevel.INFO,
                    String.format(INIT_STARTED_AGENT_ATTACHED, VMPID, APPLICATION_UUID, attachmentType),
                    K2Instrumentator.class.getName()
            );

            // Set required Group
            applyRequiredGroup();
            // Set required LogLevel
            applyRequiredLogLevel();

            String userAppName = System.getenv("K2_APP_NAME");
            String userAppVersion = System.getenv("K2_APP_VERSION");
            String userAppTags = System.getenv("K2_APP_TAGS");

            try {
                String collectorVersion = IOUtils.toString(ClassLoader.getSystemResourceAsStream("k2version"), StandardCharsets.UTF_8);
                if (StringUtils.isNotBlank(collectorVersion)) {
                    K2JAVersionInfo.collectorVersion = collectorVersion;
                }
            } catch (Exception e) {
            }

            Identifier identifier = ApplicationInfoUtils.envDetection();

            if (!CollectorConfigurationUtils.getInstance().populateCollectorConfig()) {
                return false;
            }

            setUserAppInformation(userAppName, userAppVersion, userAppTags);

            continueIdentifierProcessing(identifier);
            APPLICATION_INFO_BEAN = createApplicationInfoBean(identifier);
            if(APPLICATION_INFO_BEAN == null) {
                // log appinfo not created
                logger.logInit(
                        LogLevel.ERROR,
                        APP_INFO_BEAN_NOT_CREATED,
                        K2Instrumentator.class.getName()
                );
                return false;
            }
            if (APPLICATION_INFO_BEAN == null) {
                return false;
            }
            JA_HEALTH_CHECK = new JAHealthCheck(APPLICATION_UUID);
            logger.logInit(LogLevel.INFO, AGENT_INIT_LOG_STEP_FIVE, K2Instrumentator.class.getName());

            boolean isWorking = startK2Services();
            if (!isWorking) {
                return false;
            }
            // log init finish
            logger.logInit(
                    LogLevel.INFO,
                    String.format(AGENT_INIT_SUCCESSFUL, VMPID, APPLICATION_UUID, APPLICATION_INFO_BEAN),
                    K2Instrumentator.class.getName()
            );
            System.out.println(String.format("This application instance is now being protected by K2 Agent under id %s", APPLICATION_UUID));
            AgentUtils.getInstance().getStatusLogValues().put("start-time", Instant.now().toString());
            AgentUtils.getInstance().getStatusLogValues().put("application-uuid", APPLICATION_UUID);
            AgentUtils.getInstance().getStatusLogValues().put("pid", VMPID.toString());
            AgentUtils.getInstance().getStatusLogValues().put("java-version", ManagementFactory.getRuntimeMXBean().getName());
            File cwd = new File(".");
            AgentUtils.getInstance().getStatusLogValues().put("cwd", cwd.getAbsolutePath());
            AgentUtils.getInstance().getStatusLogValues().put("cwd-permissions", String.valueOf(cwd.canWrite() && cwd.canRead()));
            return isWorking;
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, "Error in init ", e, K2Instrumentator.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR, "Error in security module init ", e, K2Instrumentator.class.getName());
        }
        return false;
    }

    /*
        TODO : This does best effort translation of loglevel from NR config log level to K2 log level.
        Proper translation or use of NR logger completely needs to be implemented.
     */
    private static void applyRequiredLogLevel() {
        String logLevel = "INFO";

        if(System.getenv().containsKey("K2_LOG_LEVEL")){
            logLevel = System.getenv().get("K2_LOG_LEVEL");
        } else if (StringUtils.isNotBlank(NewRelic.getAgent().getConfig().getValue("security.log_level"))) {
            logLevel = NewRelic.getAgent().getConfig().getValue("security.log_level");
        }

        try {
            LogWriter.setLogLevel(LogLevel.valueOf(logLevel));
        } catch (Exception e) {
            LogWriter.setLogLevel(LogLevel.INFO);
            logLevel = LogLevel.INFO.name();
        }
        AgentUtils.getInstance().getStatusLogValues().put("log-level", logLevel);
    }

    private static void applyRequiredGroup() {
        String groupName = System.getenv().get("K2_GROUP_NAME");
        if(StringUtils.isNotBlank(groupName)){
            AgentUtils.getInstance().setGroupName(groupName);
        } else if (StringUtils.isNotBlank(NewRelic.getAgent().getConfig().getValue("security.mode"))) {
            AgentUtils.getInstance().setGroupName(NewRelic.getAgent().getConfig().getValue("security.mode"));
        } else {
            AgentUtils.getInstance().setGroupName("RASP");
        }
        AgentUtils.getInstance().getStatusLogValues().put("group-name", AgentUtils.getInstance().getGroupName());
    }

    private static boolean startK2Services() throws InterruptedException, URISyntaxException {
        if (tryWebsocketConnection()) {
            return false;
        }

        logger.logInit(
                LogLevel.INFO,
                String.format(STARTING_MODULE_LOG, AgentServices.HealthCheck.name()),
                K2Instrumentator.class.getName()
        );
        HealthCheckScheduleThread.getInstance();
        logger.logInit(
                LogLevel.INFO,
                String.format(STARTED_MODULE_LOG, AgentServices.HealthCheck.name()),
                K2Instrumentator.class.getName()
        );

        PolicyPullST.instantiateDefaultPolicy();
        PolicyPullST.getInstance();
        GlobalPolicyParameterPullST.getInstance();
        logger.logInit(
                LogLevel.INFO,
                String.format(STARTING_MODULE_LOG, AgentServices.EventWritePool.name()),
                K2Instrumentator.class.getName()
        );
        boolean isWorking = eventWritePool();
        logger.logInit(
                LogLevel.INFO,
                String.format(STARTED_MODULE_LOG, AgentServices.EventWritePool.name()),
                K2Instrumentator.class.getName()
        );

        logger.logInit(LogLevel.INFO, AGENT_INIT_LOG_STEP_FIVE_END, K2Instrumentator.class.getName());
        return isWorking;
    }

    private static boolean tryWebsocketConnection() throws InterruptedException, URISyntaxException {
        int retries = NUMBER_OF_RETRIES;
        WSClient.getInstance().openConnection();
        while (retries > 0) {
            try {
                if (!WSClient.isConnected()) {
                    retries--;
                    int timeout = (NUMBER_OF_RETRIES - retries);
                    logger.logInit(LogLevel.INFO, String.format("WS client connection failed will retry after %s minute(s)", timeout), K2Instrumentator.class.getName());
                    TimeUnit.MINUTES.sleep(timeout);
                    WSClient.reconnectWSClient();
                } else {
                    break;
                }
            } catch (Throwable e) {
                logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
                        K2Instrumentator.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
                        K2Instrumentator.class.getName());

            }
        }
        if (!WSClient.isConnected()) {
            return true;
        }
        return false;
    }

    private static void continueIdentifierProcessing(Identifier identifier) {
        // TODO : Alternative of nodeID and nodeIP needed here
        if (IdentifierEnvs.HOST.equals(identifier.getKind())) {
            identifier.setId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
        }
        identifier.setNodeId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
        identifier.setNodeIp(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeIp());
        identifier.setNodeName(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeName());
    }

    private static void setUserAppInformation(String userAppName, String userAppVersion, String userAppTags) {
        if (StringUtils.isNotBlank(userAppName)) {
            List<String> tags = Collections.emptyList();
            if (StringUtils.isNotBlank(userAppTags)) {
                tags = Arrays.asList(StringUtils.split(userAppTags, ","));
            }
            AgentUtils.getInstance().setApplicationInfo(new PolicyApplicationInfo(userAppName, userAppVersion, tags));
            AgentUtils.getInstance().setCollectAppInfoFromEnv(true);
        }
    }

    public static boolean setK2HomePath() {

        if (System.getenv().containsKey("K2_HOME")) {
            K2_HOME = System.getenv("K2_HOME");
        } else if (NewRelic.getAgent().getConfig().getValue("security.sec_home_path") != null) {
            K2_HOME = NewRelic.getAgent().getConfig().getValue("security.sec_home_path");
        } else if (NewRelic.getAgent().getConfig().getValue("newrelic.home") != null) {
            K2_HOME = NewRelic.getAgent().getConfig().getValue("newrelic.home");
        } else if (CommonUtils.getNRAgentJarDirectory() != null) {
            K2_HOME = CommonUtils.getNRAgentJarDirectory();
        } else {
            K2_HOME = ".";
        }
        Path k2homePath = Paths.get(K2_HOME, "k2home");
        CommonUtils.forceMkdirs(k2homePath, "rwxrwxrwx");
        K2_HOME = k2homePath.toString();
        AgentUtils.getInstance().getStatusLogValues().put("k2-home", K2_HOME);
        AgentUtils.getInstance().getStatusLogValues().put("k2-home-permissions", String.valueOf(k2homePath.toFile().canWrite() && k2homePath.toFile().canRead()));
        AgentUtils.getInstance().getStatusLogValues().put("agent-location", CommonUtils.getNRAgentJarDirectory());
        if (!isValidK2HomePath(K2_HOME)) {
            System.err.println("[K2-JA] Incomplete startup env parameters provided : Missing or Incorrect K2_HOME. Collector exiting.");
            return false;
        }
        return true;
    }

    private static boolean isValidK2HomePath(String k2Home) {
        if (StringUtils.isNotBlank(k2Home) && Paths.get(k2Home).toFile().isDirectory()) {
            long avail = 0;
            try {
                avail = Files.getFileStore(Paths.get(k2Home)).getUsableSpace();
            } catch (Exception e) {
//                logger.logInit(LogLevel.WARN, "Can't determine disk space available to this Java virtual machine.", K2Instrumentator.class.getName());
                return true;
            }

            if (avail > FileUtils.ONE_GB) {
//                logger.logInit(LogLevel.INFO, String.format("Disk space available to this Java virtual machine on the file store : %s", FileUtils.byteCountToDisplaySize(avail)), K2Instrumentator.class.getName());
                return true;
            }
//            logger.logInit(LogLevel.FATAL, String.format("Insufficient disk space available to the location %s is : %s", k2Home, FileUtils.byteCountToDisplaySize(avail)), K2Instrumentator.class.getName());
            System.err.println(String.format("[K2-JA] Insufficient disk space available to the location %s is : %s", k2Home, FileUtils.byteCountToDisplaySize(avail)));
            return false;
        }
        return false;
    }

    private static boolean eventWritePool() {
        try {
            EventSendPool.getInstance();
            return true;
        } catch (Throwable e) {
            logger.log(LogLevel.WARN, EXCEPTION_OCCURED_IN_EVENT_SEND_POOL, e, K2Instrumentator.class.getName());
            return false;
        }
    }

    /**
     * Gather all required information of current process.
     * Generates an {@link ApplicationInfoBean} using the information
     *
     * @param identifier
     *          runtime environment identifier.
     * @return
     */
    public static ApplicationInfoBean createApplicationInfoBean(Identifier identifier) {
        // log appinfo create started
        logger.logInit(
                LogLevel.INFO,
                APP_INFO_GATHERING_STARTED,
                K2Instrumentator.class.getName()
        );
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID, APPLICATION_UUID,
                    isDynamicAttach ? DYNAMIC : STATIC);
            applicationInfoBean.setStartTime(runtimeMXBean.getStartTime());
            identifier.setCollectorIp(getIpAddress());
            // TODO: Need to write platform agnostic alternative for this.
            applicationInfoBean.setCmdline(new ArrayList<>(Arrays.asList(getCmdLineArgsByProc().split("(\\s+)|(\0+)"))));

            //TODO remove use of proc
            try {
                applicationInfoBean.setBinaryPath(Files
                        .readSymbolicLink(
                                new File(String.format(PROC_S_EXE, applicationInfoBean.getPid())).toPath())
                        .toString());
                applicationInfoBean
                        .setBinaryName(FileUtils.readFileToString(new File(String.format(PROC_S_COMM, applicationInfoBean.getPid())), StandardCharsets.UTF_8));
                applicationInfoBean.setSha256(HashGenerator.getChecksum(new File(applicationInfoBean.getBinaryPath())));
            } catch (IOException e) {
            }

            populateEnvInfo(identifier);
            applicationInfoBean.setIdentifier(identifier);
            setApplicationInfo(applicationInfoBean);

            // log appinfo gathering ended
            logger.logInit(
                    LogLevel.INFO,
                    String.format(APP_INFO_GATHERING_FINISHED, VMPID),
                    K2Instrumentator.class.getName()
            );
            return applicationInfoBean;
        } catch (Throwable e) {
            logger.log(LogLevel.WARN, EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN, e,
                    K2Instrumentator.class.getName());
        }
        return null;
    }

    public static void setApplicationInfo(ApplicationInfoBean applicationInfoBean) {
        if (AgentUtils.getInstance().getApplicationInfo() != null) {
            applicationInfoBean.setUserProvidedApplicationInfo(AgentUtils.getInstance().getApplicationInfo());
        }
    }

    public static String getPodNameSpace() {
        File namespace = new File("/var/run/secrets/kubernetes.io/serviceaccount/namespace");
        if (!namespace.isFile()) {
            return StringUtils.EMPTY;
        }
        try {
            return FileUtils.readFileToString(namespace, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return StringUtils.EMPTY;
        }
    }

    private static void populateEnvInfo(Identifier identifier) {
        long bootTime = 0;
        String buildNumber = StringUtils.EMPTY;
        try {
            SystemInfo systemInfo = new SystemInfo();
            bootTime = systemInfo.getOperatingSystem().getSystemBootTime();
            buildNumber = systemInfo.getOperatingSystem().getVersionInfo().getBuildNumber();
        } catch (UnsatisfiedLinkError error) {
        }

        switch (identifier.getKind()) {
            case HOST:
                HostProperties hostProperties = new HostProperties();
                // TODO : Alternative of nodeID and nodeIP needed here
                hostProperties.setId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
                hostProperties.setOs(SystemUtils.OS_NAME);
                hostProperties.setArch(SystemUtils.OS_ARCH);
                hostProperties.setVersion(SystemUtils.OS_VERSION);
                hostProperties.setState("Running");
                hostProperties.setIpAddress(identifier.getCollectorIp());
                hostProperties.setName(StringUtils.isNotBlank(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeName()) ?
                        CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeName() :
                        SystemUtils.getHostName());
                hostProperties.setCreationTimestamp(bootTime * 1000);
                hostProperties.setBuildNumber(buildNumber);
                identifier.setEnvInfo(hostProperties);
                break;
            case CONTAINER:
                ContainerProperties containerProperties = new ContainerProperties();
                containerProperties.setId(identifier.getId());
                containerProperties.setName(SystemUtils.getHostName());
                containerProperties.setIpAddress(identifier.getCollectorIp());
                containerProperties.setCreationTimestamp(bootTime * 1000);
                identifier.setEnvInfo(containerProperties);
                break;
            case POD:
                PodProperties podProperties = new PodProperties();
                podProperties.setId(identifier.getId());
                podProperties.setIpAddress(identifier.getCollectorIp());
                podProperties.setNamespace(getPodNameSpace());
                podProperties.setName(SystemUtils.getHostName());
                podProperties.setCreationTimestamp(bootTime * 1000);
                ContainerProperties containerProperty = new ContainerProperties();
                containerProperty.setId(ApplicationInfoUtils.getContainerID());
                podProperties.setContainerProperties(Collections.singletonList(containerProperty));
                identifier.setEnvInfo(podProperties);
                break;
            case ECS:
                identifier.setEnvInfo(populateECSInfo(identifier));
                break;
            case FARGATE:
            case LAMBDA:
                break;
        }
    }

    private static ECSProperties populateECSInfo(Identifier identifier) {
        ECSProperties ecsProperties = new ECSProperties();
        ecsProperties.setId(identifier.getId());
        ecsProperties.setIpAddress(identifier.getCollectorIp());
        JSONObject ecsData = getECSInfo();
        SystemInfo systemInfo = new SystemInfo();
        ecsProperties.setCreationTimestamp(systemInfo.getOperatingSystem().getSystemBootTime() * 1000);

        if (ecsData != null) {
            String imageId = (String) ecsData.get("ImageID");
            if (imageId != null) {
                ecsProperties.setImageId(imageId);
            }
            String imageName = (String) ecsData.get("Image");
            if (imageName != null) {
                ecsProperties.setImageName(imageName);
            }
            JSONObject labels = (JSONObject) ecsData.get("Labels");
            if (labels != null) {
                String containerName = (String) labels.get("com.amazonaws.ecs.container-name");
                if (containerName != null) {
                    ecsProperties.setContainerName(containerName);
                }
                String ecsTaskDefinitionFamily = (String) labels.get("com.amazonaws.ecs.task-definition-family");
                String ecsTaskDefinitionVersion = (String) labels.get("com.amazonaws.ecs.task-definition-version");
                if (ecsTaskDefinitionFamily != null && ecsTaskDefinitionVersion != null) {
                    ecsProperties.setEcsTaskDefinition(ecsTaskDefinitionFamily + ":" + ecsTaskDefinitionVersion);
                }
            }
        }
        return ecsProperties;
    }

    private static JSONObject getECSInfo() {
        try {
            String url = System.getenv("ECS_CONTAINER_METADATA_URI");
            HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
            String response = new String(IOUtils.readFully(httpClient.getInputStream(), httpClient.getInputStream().available()));
            JSONParser parser = new JSONParser();
            JSONObject json = (JSONObject) parser.parse(response);
            return json;
        } catch (ParseException | IOException e) {
            return null;
        }
    }

    public static String getIpAddress() {
        try {
            String ip = detectDefaultGatewayIPViaUDP();
            if (StringUtils.isBlank(ip)) {
                ip = InetAddress.getLocalHost().getHostAddress();
            }
            return ip;
        } catch (UnknownHostException e) {
            return StringUtils.EMPTY;
        }
    }

    private static String detectDefaultGatewayIPViaUDP() {
        String ipAddress = StringUtils.EMPTY;
        try (final DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
            ipAddress = socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format("Error getting IP Address via UDP : %s : %s", e.getMessage(), e.getCause()), K2Instrumentator.class.getName());
        }
        return ipAddress;
    }

    private static String getCmdLineArgsByProc() {
        File cmdlineFile = new File(PROC_SELF_DIR + CMD_LINE_DIR);
        if (!cmdlineFile.isFile())
            return StringUtils.EMPTY;
        try {
            String cmdline = FileUtils.readFileToString(cmdlineFile,
                    StandardCharsets.UTF_8);
            if (!cmdline.isEmpty())
                return cmdline;
        } catch (IOException e) {
        }
        return StringUtils.EMPTY;
    }

    private static String getStartTimeByProc(Integer pid) {
        File statFile = new File(PROC_DIR + pid + STAT);
        if (!statFile.isFile())
            return null;
        try {
            List<String> fileData = FileUtils.readLines(statFile, StandardCharsets.UTF_8);
            String statData = fileData.get(0);
            if (!statData.isEmpty()) {
                String[] statArray = statData.split("\\s+");
                if (statArray.length >= 21) {
                    return statArray[21];
                }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    public static boolean refresh() {
        NewRelic.getAgent().getLogger().log(Level.INFO, "NR agent refresh received!!!.");
        logger.log(LogLevel.INFO, "NR agent refresh received!!!", K2Instrumentator.class.getName());
        String entityGuid = NewRelic.getAgent().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY);
        if (!AgentUtils.getInstance().isStandaloneMode() && StringUtils.isBlank(entityGuid)) {
            AgentUtils.getInstance().setAgentActive(false);
            NewRelic.getAgent().getLogger().log(Level.SEVERE, "K2 security module aborted!!! since entity.guid is not known.");
            return false;
        }
        AgentUtils.getInstance().setLinkingMetadata(NewRelic.getAgent().getLinkingMetadata());
        AgentUtils.getInstance().getLinkingMetadata().put("agentRunId", NewRelic.getAgent().getConfig().getValue(INRSettingsKey.AGENT_RUN_ID));
        AgentUtils.getInstance().setAgentActive(true);

        // Set required Group
        applyRequiredGroup();
        // Set required LogLevel
        applyRequiredLogLevel();

        if (!CollectorConfigurationUtils.getInstance().populateCollectorConfig()) {
            return false;
        }

        try {
            HttpClient.getInstance().resetClientURL();
            if (WSClient.getInstance().getURI().compareTo(new URI(CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getValidatorServiceEndpointURL())) != 0) {
                WSClient.reconnectWSClient();
            }
        } catch (URISyntaxException | InterruptedException e) {
            NewRelic.getAgent().getLogger().log(Level.SEVERE, "WS Server re-instantiation fails due to {1}", e.getMessage());
            logger.log(LogLevel.ERROR, String.format("WS Server re-instantiation fails due to %s", e.getMessage()), K2Instrumentator.class.getName());
            return false;
        }

        PolicyPullST.instantiateDefaultPolicy();
        return true;
    }

    public static void agentInactive() {
        AgentUtils.getInstance().setAgentActive(false);
        ShutDownEvent shutDownEvent = new ShutDownEvent();
        shutDownEvent.setApplicationUUID(K2Instrumentator.APPLICATION_UUID);
        shutDownEvent.setStatus(IAgentConstants.TERMINATING);
        EventSendPool.getInstance().sendEvent(shutDownEvent.toString());
        logger.log(LogLevel.INFO, IAgentConstants.SHUTTING_DOWN_WITH_STATUS + shutDownEvent, K2Instrumentator.class.getName());
    }

}
