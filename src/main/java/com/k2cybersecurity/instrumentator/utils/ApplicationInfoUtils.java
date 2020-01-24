package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CGROUP_FILE_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.KUBEPODS_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PROC_DIR;

public class ApplicationInfoUtils {

	public static final String SELF_NET_ROUTE = "self/net/route";
	public static final String CS_1 = "00000000";
	public static final String DOT = ".";

	public static void updateServerInfo() {
		Set<DeployedApplication> deployedApplications = getAllDeployedApplications();
		Boolean resend = false;
		for (DeployedApplication deployedApplication : deployedApplications) {
			if (!K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()
					.contains(deployedApplication)) {
				HashGenerator.updateShaAndSize(deployedApplication);
				K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()
						.add(deployedApplication);
				resend = true;
			}
		}
		if (resend) {
			EventSendPool.getInstance().sendEvent(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
		}
	}

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

	public static String getPodId(String containerId) throws IOException {
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
		} catch (Exception e) {
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
	}

	public static String getHostName() throws IOException {
		File hostName = new File("/etc/hostname");
		try {
			return FileUtils.readFileToString(hostName).trim();
		} catch (Exception e) {
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

	public static void main(String[] args) throws IOException {
		try {
			System.out.println(getDefaultGateway());
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static Set<DeployedApplication> getAllDeployedApplications() {
		// TODO Auto-generated method stub
		return null;
	}

	public static boolean isK8sEnv() {
		String k8sHost = System.getenv("KUBERNETES_SERVICE_HOST");
		if (StringUtils.isNotBlank(k8sHost)) {
			return true;
		}
		return false;
	}

}
