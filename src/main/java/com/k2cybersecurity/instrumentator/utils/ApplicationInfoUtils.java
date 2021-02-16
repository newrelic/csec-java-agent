package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.CollectorConfig;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.NodeLevelConfig;
import com.k2cybersecurity.intcodeagent.models.javaagent.Identifier;
import com.k2cybersecurity.intcodeagent.models.javaagent.IdentifierEnvs;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class ApplicationInfoUtils {

	public static final String SELF_NET_ROUTE = "self/net/route";
	public static final String CS_1 = "00000000";
	public static final String DOT = ".";
	private static final String SCOPE = ".scope";
	private static final String DOCKER_1_13 = "/docker-";
	public static final String LIBPOD = "/libpod-";

	public static String getDefaultGateway() throws IOException {
		try {
			List<String> routes = IOUtils.readLines(new FileInputStream(new File(PROC_DIR + SELF_NET_ROUTE)));
			for (int i = 1; i < routes.size(); i++) {
				String[] route = routes.get(i).split("\\s+");
				if (StringUtils.equals(CS_1, route[1])) {
					return getDefaultGateway(route[2]);
				}
			}
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
	}

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
		try (FileInputStream fileInputStream = new FileInputStream(cgroupFile)) {
			List<String> cgroupEntries = IOUtils.readLines(fileInputStream);
			for (String line : cgroupEntries) {
				int index = line.indexOf(KUBEPODS_DIR);
				if (index > -1) {
					String[] fields = StringUtils.split(line, File.separator);
					if (StringUtils.isNotBlank(fields[fields.length - 2])) {
						return fields[fields.length - 2];
					}
				}
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
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
		if (StringUtils.equals(System.getenv("AWS_EXECUTION_ENV"), "AWS_ECS_FARGATE")) {
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
		Identifier identifier = new Identifier(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeName(), CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId(), CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeIp());
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
			identifier.setId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
		}
		return identifier;
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
