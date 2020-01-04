package com.k2cybersecurity.instrumentator;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CGROUP_FILE_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CMD_LINE_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DIR_SEPERATOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DOCKER_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HOST_IP_PROPERTIES_FILE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.KUBEPODS_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.LXC_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PROC_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.STAT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.VMPID_SPLIT_CHAR;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IPScheduledThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

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
			System.err.println("Error while initialising the K2 Agent :" + th.getCause() + " : " + th.getMessage());
		}
	}

	private static void init() {
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
			logger.log(LogLevel.ERROR, "Error occured while trying to connect to wsocket: ", e,
					AgentNew.class.getName());
		}
		IPScheduledThread.getInstance();
		eventWritePool();
	}

	private static void eventWritePool() {

		try {
			EventSendPool.getInstance();
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Exception occured in EventSendPool: ", e, AgentNew.class.getName());
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
					isDynamicAttach ? "DYNAMIC" : "STATIC");
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
								new File(String.format("/proc/%s/exe", applicationInfoBean.getPid())).toPath())
						.toString());
			} catch (IOException e) {
			}
			applicationInfoBean
					.setBinaryName(StringUtils.substringAfterLast(applicationInfoBean.getBinaryPath(), File.separator));
			applicationInfoBean
					.setSha256(HashGenerator.getChecksum(new File(applicationInfoBean.getBinaryPath())));
			if (containerId != null) {
				applicationInfoBean.setContainerID(containerId);
				applicationInfoBean.setIsHost(false);
			} else
				applicationInfoBean.setIsHost(true);
			// applicationInfoBean.setJvmArguments(new
			// JSONArray(runtimeMXBean.getInputArguments()));
			return applicationInfoBean;
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Exception occured in createApplicationInfoBean: ", e,
					AgentNew.class.getName());
		}
		return null;
	}

	private static String getCmdLineArgsByProc(Integer pid) {
		File cmdlineFile = new File(PROC_DIR + pid + CMD_LINE_DIR);
		if (!cmdlineFile.isFile())
			return null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(cmdlineFile));
			String cmdline = br.readLine();
			if (!cmdline.isEmpty())
				return cmdline;
		} catch (IOException e) {
		} finally {
			try {
				br.close();
			} catch (IOException e) {
			}
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
