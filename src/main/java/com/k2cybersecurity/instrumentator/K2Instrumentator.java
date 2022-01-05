package com.k2cybersecurity.instrumentator;

import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.*;
import com.k2cybersecurity.intcodeagent.constants.AgentServices;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.models.config.PolicyApplicationInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.schedulers.PolicyPullST;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
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
import java.net.URL;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class K2Instrumentator {

    private static final String APP_INFO_GATHERING_FINISHED = "[APP_INFO] Application info generated : %s.";
    private static final String APP_INFO_GATHERING_STARTED = "[STEP-3][BEGIN][APP_INFO] Gathering application info for current process.";
    private static final String APP_INFO_BEAN_NOT_CREATED = "[APP_INFO] Error K2 application info bean not created.";
    private static final String AGENT_INIT_SUCCESSFUL = "[STEP-2][PROTECTION][COMPLETE] Protecting new process with PID %s and UUID %s : %s.";

    private static final String INIT_STARTED_AGENT_ATTACHED = "[STEP-2][PROTECTION][BEGIN] K2 Java collector attached to process: PID = %s, with generated applicationUID = %s by %s attachment";

    public static Integer VMPID;
    public static final String APPLICATION_UUID = UUID.randomUUID().toString();
    public static ApplicationInfoBean APPLICATION_INFO_BEAN;
    public static JAHealthCheck JA_HEALTH_CHECK;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static boolean isDynamicAttach = false;
    public static boolean enableHTTPRequestPrinting = false;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    static {
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            String runningVM = runtimeMXBean.getName();
            VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
        } catch (Throwable th) {
            logger.log(LogLevel.ERROR, ERROR_WHILE_INITIALISING_THE_K2_AGENT + th.getCause() + " : " + th.getMessage(), K2Instrumentator.class.getName());
        }
    }

    public static boolean init(Boolean isDynamicAttach) {
        try {
            K2Instrumentator.isDynamicAttach = isDynamicAttach;
            String attachmentType = isDynamicAttach ? DYNAMIC : STATIC;
            // log init
            logger.logInit(
                    LogLevel.INFO,
                    String.format(INIT_STARTED_AGENT_ATTACHED, VMPID, APPLICATION_UUID, attachmentType),
                    K2Instrumentator.class.getName()
            );
            String groupName = System.getenv("K2_GROUP_NAME");
            if (StringUtils.isBlank(groupName)) {
                logger.log(LogLevel.ERROR, "Incomplete startup env parameters provided: Missing K2_GROUP_NAME", K2Instrumentator.class.getName());
                System.err.println("[K2 Java Collector] Incomplete startup env parameters provided : Missing K2_GROUP_NAME. Collector exiting.");
                return false;
            } else {
                AgentUtils.getInstance().setGroupName(groupName);
            }

            String nlcPath = System.getenv("K2_AGENT_NODE_CONFIG");
            String alcPath = System.getenv("K2_AGENT_APP_CONFIG");
            String userAppName = System.getenv("K2_APP_NAME");
            String userAppVersion = System.getenv("K2_APP_VERSION");
            String userAppTags = System.getenv("K2_APP_TAGS");

            String nlcDefaultPath = new File(osVariables.getConfigPath(), "node-level-config.yaml").toString();
            String alcDefaultPath = new File(osVariables.getConfigPath(), "application-level-config.yaml").toString();
            if (StringUtils.isBlank(nlcPath)) {
                nlcPath = nlcDefaultPath;
            }
            if (StringUtils.isBlank(alcPath)) {
                alcPath = alcDefaultPath;
            }

            Identifier identifier = ApplicationInfoUtils.envDetection();

            if (!CollectorConfigurationUtils.getInstance().readCollectorConfig(identifier.getKind(), nlcPath, alcPath)) {
                return false;
            }

            if (IdentifierEnvs.HOST.equals(identifier.getKind())) {
                identifier.setId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
            }

            if (StringUtils.isNotBlank(userAppName)) {
                List<String> tags = Collections.emptyList();
                if (StringUtils.isNotBlank(userAppTags)) {
                    tags = Arrays.asList(StringUtils.split(userAppTags, ","));
                }
                AgentUtils.getInstance().setApplicationInfo(new PolicyApplicationInfo(userAppName, userAppVersion, tags));
                AgentUtils.getInstance().setCollectAppInfoFromEnv(true);
            }

            identifier.setNodeId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
            identifier.setNodeIp(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeIp());
            identifier.setNodeName(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeName());
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
                        continue;
                    }
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
                            K2Instrumentator.class.getName());
                }
            }
            if (!WSClient.isConnected()) {
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

            DirectoryWatcher.startMonitorDaemon();
            PolicyPullST.instantiateDefaultPolicy();
            PolicyPullST.getInstance();
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
            logger.logInit(
                    LogLevel.INFO,
                    String.format(STARTING_MODULE_LOG, AgentServices.DirectoryWatcher.name()),
                    K2Instrumentator.class.getName()
            );
            logger.logInit(
                    LogLevel.INFO,
                    String.format(STARTED_MODULE_LOG, AgentServices.DirectoryWatcher.name()),
                    K2Instrumentator.class.getName()
            );
            logger.logInit(LogLevel.INFO, AGENT_INIT_LOG_STEP_FIVE_END, K2Instrumentator.class.getName());
            // log init finish
            logger.logInit(
                    LogLevel.INFO,
                    String.format(AGENT_INIT_SUCCESSFUL, VMPID, APPLICATION_UUID, APPLICATION_INFO_BEAN),
                    K2Instrumentator.class.getName()
            );
            System.out.println(String.format("This application instance is now being protected by K2 Agent under id %s", APPLICATION_UUID));
            return isWorking;
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, "Error in init ", e, K2Instrumentator.class.getName());
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

}
