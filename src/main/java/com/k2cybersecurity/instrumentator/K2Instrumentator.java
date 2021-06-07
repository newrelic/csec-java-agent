package com.k2cybersecurity.instrumentator;

import com.k2cybersecurity.instrumentator.custom.ClassloaderAdjustments;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.ApplicationInfoUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.apache.commons.text.StringEscapeUtils;
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
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class K2Instrumentator {

    public static Integer VMPID;
    public static final String APPLICATION_UUID = UUID.randomUUID().toString();
    public static ApplicationInfoBean APPLICATION_INFO_BEAN;
    public static JAHealthCheck JA_HEALTH_CHECK;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static boolean isDynamicAttach = false;
    public static boolean enableHTTPRequestPrinting = false;

    public static boolean isk8sEnv = false;
    public static boolean isECSEnv = false;

    public static String nlcDefaultPath = "/opt/k2-ic/node-level-config.yaml";

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
            if (StringUtils.isBlank(nlcPath)) {
                nlcPath = nlcDefaultPath;
            }
            if (StringUtils.isBlank(alcPath)) {
                alcPath = StringUtils.EMPTY;
            }

            Identifier identifier = ApplicationInfoUtils.envDetection();

            if (!CollectorConfigurationUtils.getInstance().readCollectorConfig(identifier.getKind(), nlcPath, alcPath)) {
                return false;
            }
            identifier.setNodeId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
            identifier.setNodeIp(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeIp());
            identifier.setNodeName(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeName());
            APPLICATION_INFO_BEAN = createApplicationInfoBean(identifier);

            if (APPLICATION_INFO_BEAN == null) {
                return false;
            }
            JA_HEALTH_CHECK = new JAHealthCheck(APPLICATION_UUID);

            new Thread(() -> {
                try {
                    WSClient.getInstance();
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
                            K2Instrumentator.class.getName());
                }
                HealthCheckScheduleThread.getInstance();
            }).start();
            boolean isWorking = eventWritePool();

            // Place Classloader adjustments
            ClassloaderAdjustments.jbossSpecificAdjustments();

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
            logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_EVENT_SEND_POOL, e, K2Instrumentator.class.getName());
            return false;
        }
    }

    public static ApplicationInfoBean createApplicationInfoBean(Identifier identifier) {
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID, APPLICATION_UUID,
                    isDynamicAttach ? DYNAMIC : STATIC);
            applicationInfoBean.setStartTime(runtimeMXBean.getStartTime());
            identifier.setCollectorIp(getIpAddress());
            applicationInfoBean.setCmdline(StringEscapeUtils.escapeJava(getCmdLineArgsByProc()));

            try {
                applicationInfoBean.setBinaryPath(Files
                        .readSymbolicLink(
                                new File(String.format(PROC_S_EXE, applicationInfoBean.getPid())).toPath())
                        .toString());
                applicationInfoBean
                        .setBinaryName(StringUtils.substringAfterLast(applicationInfoBean.getBinaryPath(), File.separator));
                applicationInfoBean.setSha256(HashGenerator.getChecksum(new File(applicationInfoBean.getBinaryPath())));
            } catch (IOException e) {
            }

            populateEnvInfo(identifier);
            applicationInfoBean.setIdentifier(identifier);
            return applicationInfoBean;
        } catch (Throwable e) {
            logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN, e,
                    K2Instrumentator.class.getName());
        }
        return null;
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
            return null;
        try {
            String cmdline = FileUtils.readFileToString(cmdlineFile,
                    StandardCharsets.UTF_8);
            if (!cmdline.isEmpty())
                return cmdline;
        } catch (IOException e) {
        }
        return null;
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
