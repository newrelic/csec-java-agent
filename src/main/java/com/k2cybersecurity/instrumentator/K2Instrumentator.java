package com.k2cybersecurity.instrumentator;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CGROUP_FILE_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CMD_LINE_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DIR_SEPERATOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DOCKER_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DYNAMIC;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ERROR_WHILE_INITIALISING_THE_K2_AGENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.EXCEPTION_OCCURED_IN_EVENT_SEND_POOL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.KUBEPODS_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.LXC_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PROC_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PROC_S_EXE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.STAT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.STATIC;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.VMPID_SPLIT_CHAR;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

import com.k2cybersecurity.instrumentator.utils.ApplicationInfoUtils;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.Identifier;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

public class K2Instrumentator {

	public static Set<String> hookedAPIs = new HashSet<>();
	public static String hostip = StringUtils.EMPTY;
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
	
	public static boolean isk8sEnv = false;

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
		K2Instrumentator.isDynamicAttach = isDynamicAttach;
		
//		 ConfigK2Logs.getInstance().initializeLogs();
		APPLICATION_INFO_BEAN = createApplicationInfoBean();
		if(APPLICATION_INFO_BEAN == null) {
			return false;
		}
		JA_HEALTH_CHECK = new JAHealthCheck(APPLICATION_UUID);
		isk8sEnv = ApplicationInfoUtils.isK8sEnv();
		
		if(isk8sEnv) {
			hostip = System.getenv("K2_SERVICE_SERVICE_HOST");
		}else if(APPLICATION_INFO_BEAN.getIdentifier().getIsHost()){
			hostip = InetAddress.getLoopbackAddress().getHostAddress();
		}
		else {
			try {
				hostip = ApplicationInfoUtils.getDefaultGateway();
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		
		try {
			WSClient.getInstance();
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
					K2Instrumentator.class.getName());
			return false;
		}
		HealthCheckScheduleThread.getInstance();
		boolean isWorking = eventWritePool();
		System.out.println(String.format("This application instance is now being protected by K2 Agent under id %s", APPLICATION_UUID));
		return isWorking;
	}

	private static boolean eventWritePool() {

		try {
			EventSendPool.getInstance();
			return true;
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_EVENT_SEND_POOL, e, K2Instrumentator.class.getName());
			return false;
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
			Identifier identifier = new Identifier(getIpAddress());
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
			identifier.setHostname(ApplicationInfoUtils.getHostName());
			if (containerId != null) {
				identifier.setContainerId(containerId);
				identifier.setIsHost(false);
				identifier.setIsContainer(true);
				String podId = ApplicationInfoUtils.getPodId(containerId);
				if(StringUtils.isNotBlank(podId)) {
					identifier.setPodId(podId);
					identifier.setNamespace(getPodNameSpace());
					identifier.setIsPod(true);
				}
			} else {
				identifier.setIsHost(true);
			}
			// applicationInfoBean.setJvmArguments(new
			// JSONArray(runtimeMXBean.getInputArguments()));
			applicationInfoBean.setIdentifier(identifier);
			return applicationInfoBean;
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN, e,
					K2Instrumentator.class.getName());
		}
		return null;
	}
	
	private static String getIpAddress() {
		try {
			return InetAddress.getLocalHost().getHostAddress();
		} catch (UnknownHostException e) {
			return StringUtils.EMPTY;
		}
	}

	private static String getCmdLineArgsByProc(Integer pid) {
		File cmdlineFile = new File(PROC_DIR + "self" + CMD_LINE_DIR);
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
	
	public static String getPodNameSpace() {
		File namespace = new File("/var/run/secrets/kubernetes.io/serviceaccount/namespace");
		if(!namespace.isFile()) {
			return StringUtils.EMPTY;
		}
		try {
			return FileUtils.readFileToString(namespace, StandardCharsets.UTF_8);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return StringUtils.EMPTY;
		}
	}

}
