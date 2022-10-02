package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.Identifier;
import com.k2cybersecurity.intcodeagent.models.javaagent.IdentifierEnvs;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class ApplicationInfoUtils {

    public static final String DOT = ".";
    private static final String SCOPE = ".scope";
    private static final String DOCKER_1_13 = "/docker-";
    public static final String LIBPOD = "/libpod-";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

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
        } catch (Throwable e) {
            e.printStackTrace();
        }
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
                identifier.setId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
            }
            return identifier;
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, "Error while env detection ", e, ApplicationInfoUtils.class.getName());
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
}
