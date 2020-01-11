package com.k2cybersecurity.instrumentator;

import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IPScheduledThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class K2Instrumentator {

	public static Set<String> hookedAPIs = new HashSet<>();
	public static String hostip = "";
	public static Integer VMPID;
	public static final String APPLICATION_UUID = UUID.randomUUID().toString();
	public static ApplicationInfoBean APPLICATION_INFO_BEAN;
	public static JAHealthCheck JA_HEALTH_CHECK;

	private static final String SCOPE = ".scope";
	private static final String DOCKER_1_13 = "/docker-";

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static boolean isDynamicAttach = false;
	public static boolean isAttached = false;
	public static boolean enableHTTPRequestPrinting = false;

	static {
		try {
			RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
			String runningVM = runtimeMXBean.getName();
			VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
		} catch (Throwable th) {
			System.err.println(ERROR_WHILE_INITIALISING_THE_K2_AGENT + th.getCause() + " : " + th.getMessage());
		}
	}

	public static void init(Boolean isDynamicAttach) {
		K2Instrumentator.isDynamicAttach = isDynamicAttach;
		try (BufferedReader reader = new BufferedReader(new FileReader(HOST_IP_PROPERTIES_FILE))) {
			hostip = reader.readLine();
			if (hostip != null)
				hostip = hostip.trim();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
//		 ConfigK2Logs.getInstance().initializeLogs();
		APPLICATION_INFO_BEAN = createApplicationInfoBean();
		JA_HEALTH_CHECK = new JAHealthCheck(APPLICATION_UUID);
		try {
			WSClient.getInstance();
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
					AgentNew.class.getName());
		}
		IPScheduledThread.getInstance();
		eventWritePool();
	}

	private static void eventWritePool() {

		try {
			EventSendPool.getInstance();
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_EVENT_SEND_POOL, e, AgentNew.class.getName());
		}
	}

	public static String getContainerID() {

		File cgroupFile = new File(CGROUP_FILE_NAME);
		if (!cgroupFile.isFile())
			return null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(cgroupFile));
		} catch (FileNotFoundException e) {
			return null;
		}

		String st;
		int index = -1;
		try {
			while ((st = br.readLine()) != null) {
				index = st.lastIndexOf(DOCKER_DIR);
				if (index > -1) {
					return st.substring(index + 7);
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
				// docker version 1.13.1
				index = st.lastIndexOf(DOCKER_1_13);
				int indexEnd = st.lastIndexOf(SCOPE);
				if (index > -1 && indexEnd > -1) {
					return st.substring(index + 8, indexEnd);
				}
			}

		} catch (IOException e) {
			return null;
		} finally {
			try {
				br.close();
			} catch (IOException e) {
			}
		}
		return null;
	}

	public static ApplicationInfoBean createApplicationInfoBean() {
		try {
			RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
			ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID, APPLICATION_UUID,
					isDynamicAttach ? DYNAMIC : STATIC);
			applicationInfoBean.setStartTime(runtimeMXBean.getStartTime());
			String containerId = getContainerID();
			String cmdLine = StringEscapeUtils.escapeJava(getCmdLineArgsByProc(VMPID));
			applicationInfoBean.setProcStartTime(getStartTimeByProc(VMPID));
			applicationInfoBean.setCmdline(cmdLine);
			// if (cmdLine != null) {
			// List<String> cmdlineArgs = Arrays.asList(cmdLine.split(NULL_CHAR_AS_STRING));
			// JSONArray jsonArray = new JSONArray();
			// jsonArray.addAll(cmdlineArgs);
			// applicationInfoBean.setJvmArguments(jsonArray);
			// }
			try {
				applicationInfoBean.setBinaryPath(Files
						.readSymbolicLink(
								new File(String.format(PROC_S_EXE, applicationInfoBean.getPid())).toPath())
						.toString());
			} catch (IOException e) {
			}
			applicationInfoBean
					.setBinaryName(StringUtils.substringAfterLast(applicationInfoBean.getBinaryPath(), File.separator));
			applicationInfoBean.setSha256(HashGenerator.getChecksum(new File(applicationInfoBean.getBinaryPath())));
			if (containerId != null) {
				applicationInfoBean.setContainerID(containerId);
				applicationInfoBean.setIsHost(false);
			} else
				applicationInfoBean.setIsHost(true);
			// applicationInfoBean.setJvmArguments(new
			// JSONArray(runtimeMXBean.getInputArguments()));
			return applicationInfoBean;
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN, e,
					AgentNew.class.getName());
		}
		return null;
	}

	private static String getCmdLineArgsByProc(Integer pid) {
		File cmdlineFile = new File(PROC_DIR + pid + CMD_LINE_DIR);
		if (!cmdlineFile.isFile())
			return null;
		try {
			String cmdline = FileUtils.readFileToString(new File(PROC_DIR + pid + CMD_LINE_DIR),
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
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(statFile));
			String statData = br.readLine();
			if (!statData.isEmpty()) {
				String[] statArray = statData.split("\\s+");
				if (statArray.length >= 21) {
					return statArray[21];
				}
			}
		} catch (IOException e) {
		} finally {
			try {
				br.close();
			} catch (IOException e) {
			}
		}
		return null;
	}

}
