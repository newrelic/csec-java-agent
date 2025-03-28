package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.javaagent.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import oshi.SystemInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.URL;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.*;
import static com.newrelic.agent.security.util.IUtilConstants.NOT_AVAILABLE;

public class ApplicationInfoUtils {

    public static final String DOT = ".";
    private static final String SCOPE = ".scope";
    private static final String DOCKER_1_13 = "/docker-";
    public static final String LIBPOD = "/libpod-";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static final String APP_INFO_GATHERING_FINISHED = "[APP_INFO] Application info generated for pid : %s.";
    private static final String APP_INFO_GATHERING_STARTED = "[STEP-3][BEGIN][APP_INFO] Gathering application info for current process.";

    public static String getContainerID() {

        File cgroupFile = new File(CGROUP_FILE_NAME);
        if (!cgroupFile.isFile())
            return null;
        try {
            List<String> fileData = FileUtils.readLines(cgroupFile, StandardCharsets.UTF_8);
            Iterator<String> itr = fileData.iterator();
            int index = -1;
            while (itr.hasNext()) {
                String st = itr.next();
                index = st.lastIndexOf(DOCKER_DIR);
                if (index > -1) {
                    return st.substring(index + 7);
                }
                index = st.lastIndexOf(ECS_DIR);
                if (index > -1) {
                    return st.substring(st.lastIndexOf(DIR_SEPERATOR) + 1);
                }
                index = st.indexOf(KUBEPODS_DIR);
                if (index > -1) {
                    return st.substring(st.lastIndexOf(DIR_SEPERATOR) + 1);
                }
                // To support docker older versions
                index = st.lastIndexOf(LXC_DIR);
                if (index > -1) {
                    return st.substring(index + 4);
                }
                // cgroup driver systemd
                index = st.lastIndexOf(DOCKER_1_13);
                int indexEnd = st.lastIndexOf(SCOPE);
                if (index > -1 && indexEnd > -1) {
                    return st.substring(index + 8, indexEnd);
                }

                // podman
                String containerId = StringUtils.substringBetween(st, LIBPOD, SCOPE);
                if (StringUtils.isNotBlank(containerId)) {
                    return containerId;
                }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    public static String getPodId() {
        File cgroupFile = new File(CGROUP_FILE_NAME);
        String podId = StringUtils.EMPTY;
        try (FileInputStream fileInputStream = new FileInputStream(cgroupFile)) {
            List<String> cgroupEntries = IOUtils.readLines(fileInputStream, StandardCharsets.UTF_8);
            for (String line : cgroupEntries) {
                int index = line.indexOf(KUBEPODS_DIR);
                if (index > -1) {
                    String[] fields = StringUtils.split(line, File.separator);
                    if (StringUtils.isNotBlank(fields[fields.length - 2])) {
                        podId = fields[fields.length - 2];
                    }
                }
                index = line.indexOf(KUBEPODS_SLICE_DIR);
                if (index > -1) {
                    podId = StringUtils.substringBetween(line, "kubepods-besteffort-pod", ".slice");
                }
            }
        } catch (Throwable ignored) {}
        return StringUtils.replaceChars(podId, "_", "-");
    }

    private static String getDefaultGateway(String hexGateway) {

        StringBuilder gateway = new StringBuilder();
        for (int i = hexGateway.length() - 2; i >= 0; i -= 2) {
            String hex = StringUtils.substring(hexGateway, i, i + 2);
            gateway.append(Integer.parseInt(hex, 16));
            gateway.append(DOT);
        }
        return StringUtils.removeEnd(gateway.toString(), DOT);
    }


    public static boolean isK8sEnv() {
        String k8sHost = System.getenv("KUBERNETES_SERVICE_HOST");
        if (StringUtils.isNotBlank(k8sHost)) {
            return true;
        }
        return false;
    }

    public static boolean isECSEnv() {
        if (StringUtils.startsWith(System.getenv("AWS_EXECUTION_ENV"), "AWS_ECS")) {
            return true;
        }
        return false;
    }


    public static Identifier envDetection() {

		/*
		Supported :
		1. Host
		2. Docker container
		3. Pod
		4. ECS
		5. Fargate (To be done)
		* */
        try {
            Identifier identifier = new Identifier();
            String containerId = getContainerID();
            if (isECSEnv()) {
                identifier.setKind(IdentifierEnvs.ECS);
                identifier.setId(getECSTaskId());
            } else if (isK8sEnv()) {
                identifier.setKind(IdentifierEnvs.POD);
                identifier.setId(getPodId());
            } else if (StringUtils.isNotBlank(containerId)) {
                identifier.setKind(IdentifierEnvs.CONTAINER);
                identifier.setId(containerId);
            } else {
                identifier.setKind(IdentifierEnvs.HOST);
                // TODO: find alternate nodeId for this case.
            }
            return identifier;
        } catch (Exception e) {
            logger.log(LogLevel.SEVERE, "Error while env detection ", e, ApplicationInfoUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE, "Error while env detection ", e, ApplicationInfoUtils.class.getName());
        }
        return null;
    }

    private static String getECSTaskId() {

        File cgroupFile = new File(CGROUP_FILE_NAME);
        if (!cgroupFile.isFile())
            return null;
        try {
            List<String> fileData = FileUtils.readLines(cgroupFile, StandardCharsets.UTF_8);
            Iterator<String> itr = fileData.iterator();
            int index = -1;
            while (itr.hasNext()) {
                String st = itr.next();
                index = st.lastIndexOf(ECS_DIR);
                if (index > -1) {
                    return st.substring(index + 4, st.lastIndexOf(DIR_SEPERATOR));
                }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    /**
     * Gather all required information of current process.
     * Generates an {@link ApplicationInfoBean} using the information
     *
     * @param identifier
     *          runtime environment identifier.
     * @return
     */
    public static ApplicationInfoBean createApplicationInfoBean(Identifier identifier, Integer vmpid, String applicationUUID, CollectorConfig config) {
        // log appinfo create started
        logger.logInit(
                LogLevel.INFO,
                APP_INFO_GATHERING_STARTED,
                ApplicationInfoUtils.class.getName()
        );
        AgentUtils.getInstance().getStatusLogValues().put(PROCESS_BINARY, NOT_AVAILABLE);
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(vmpid, STATIC);
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
                AgentUtils.getInstance().getStatusLogValues().put(PROCESS_BINARY, applicationInfoBean.getBinaryPath());
                applicationInfoBean
                        .setBinaryName(FileUtils.readFileToString(new File(String.format(PROC_S_COMM, applicationInfoBean.getPid())), StandardCharsets.UTF_8));
                applicationInfoBean.setSha256(HashGenerator.getChecksum(new File(applicationInfoBean.getBinaryPath())));
            } catch (IOException e) {
            }

            populateEnvInfo(identifier, config);
            applicationInfoBean.setIdentifier(identifier);

            // log appinfo gathering ended
            logger.logInit(
                    LogLevel.INFO,
                    String.format(APP_INFO_GATHERING_FINISHED, vmpid),
                    ApplicationInfoUtils.class.getName()
            );
            return applicationInfoBean;
        } catch (Throwable e) {
            logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN, e,
                    ApplicationInfoUtils.class.getName());
        }
        return null;
    }

    private static void populateEnvInfo(Identifier identifier, CollectorConfig config) {
        long bootTime = 0;
        String buildNumber = StringUtils.EMPTY;
        try {
            SystemInfo systemInfo = new SystemInfo();
            bootTime = systemInfo.getOperatingSystem().getSystemBootTime();
            buildNumber = systemInfo.getOperatingSystem().getVersionInfo().getBuildNumber();
        } catch (Throwable ignored) {
        }

        switch (identifier.getKind()) {
            case HOST:
                HostProperties hostProperties = new HostProperties();
                // TODO : Alternative of nodeID and nodeIP needed here
                hostProperties.setId(config.getNodeId());
                hostProperties.setOs(SystemUtils.OS_NAME);
                hostProperties.setArch(SystemUtils.OS_ARCH);
                hostProperties.setVersion(SystemUtils.OS_VERSION);
                hostProperties.setState("Running");
                hostProperties.setIpAddress(identifier.getCollectorIp());
                hostProperties.setName(StringUtils.isNotBlank(config.getNodeName()) ? config.getNodeName() : SystemUtils.getHostName());
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
                identifier.setEnvInfo(populateECSInfo(identifier, bootTime));
                break;
            case FARGATE:
            case LAMBDA:
                break;
        }
    }

    private static ECSProperties populateECSInfo(Identifier identifier, long bootTime) {
        ECSProperties ecsProperties = new ECSProperties();
        ecsProperties.setId(identifier.getId());
        ecsProperties.setIpAddress(identifier.getCollectorIp());
        JSONObject ecsData = getECSInfo();
        ecsProperties.setCreationTimestamp(bootTime * 1000);

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
            logger.log(LogLevel.SEVERE, String.format("Error getting IP Address via UDP : %s : %s", e.getMessage(), e.getCause()), ApplicationInfoUtils.class.getName());
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

    public static void continueIdentifierProcessing(Identifier identifier, CollectorConfig config) {
        // TODO : Alternative of nodeID and nodeIP needed here
        if (IdentifierEnvs.HOST.equals(identifier.getKind())) {
            identifier.setId(config.getNodeId());
        }
        identifier.setNodeId(config.getNodeId());
        identifier.setNodeIp(config.getNodeIp());
        identifier.setNodeName(config.getNodeName());
    }
}
