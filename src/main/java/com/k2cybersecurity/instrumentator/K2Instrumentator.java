package com.k2cybersecurity.instrumentator;

import com.k2cybersecurity.instrumentator.custom.ClassloaderAdjustments;
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
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class K2Instrumentator {

	private static final String DOCKER_HYPHEN = "docker-";
	public static final String LIBPOD = "/libpod-";
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
	public static boolean isECSEnv = false;
	
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
		isk8sEnv = ApplicationInfoUtils.isK8sEnv();
		isECSEnv = ApplicationInfoUtils.isECSEnv();
		
		APPLICATION_INFO_BEAN = createApplicationInfoBean();
		if(APPLICATION_INFO_BEAN == null) {
			return false;
		}
		JA_HEALTH_CHECK = new JAHealthCheck(APPLICATION_UUID);

		
//		System.out.println("Env variables in container : ");
//		Map<String, String> allEnv = System.getenv();
//		allEnv.forEach((k, v) -> System.out.println(k + " : " + v));
		
		if (StringUtils.isNotBlank(System.getenv("K2_HOST_IP"))) {
			hostip=System.getenv("K2_HOST_IP");
		} else if(isk8sEnv) {
			hostip = System.getenv("K2_SERVICE_SERVICE_HOST");
		} else if (isECSEnv) {
			hostip = "k2-service.k2-ns";
		} else if(APPLICATION_INFO_BEAN.getIdentifier().getIsHost()){
			hostip = InetAddress.getLoopbackAddress().getHostAddress();
		}else {
			try {
				hostip = ApplicationInfoUtils.getDefaultGateway();
			} catch (IOException e) {
				logger.log(LogLevel.ERROR, ERROR_WHILE_DETERMINING_HOSTIP_FROM_DEFAULT_GATEWAY, e,
						K2Instrumentator.class.getName());
				return false;
			}
		}
		try {
			WSClient.getInstance();
		} catch (Throwable e) {
			logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
					K2Instrumentator.class.getName());
			return false;
		}

		HealthCheckScheduleThread.getInstance();
		boolean isWorking = eventWritePool();

		// Place Classloader adjustments
		ClassloaderAdjustments.jbossSpecificAdjustments();

		System.out.println(String.format("This application instance is now being protected by K2 Agent under id %s", APPLICATION_UUID));
		return isWorking;
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
				// docker version 1.13.1
				index = st.lastIndexOf(DOCKER_1_13);
				int indexEnd = st.lastIndexOf(SCOPE);
				if (index > -1 && indexEnd > -1) {
					return st.substring(index + 8, indexEnd);
				}

				// podman
				String containerId = StringUtils.substringBetween(st, LIBPOD, SCOPE);
				if(StringUtils.isNotBlank(containerId)){
					return containerId;
				}
				
				//cgroup driver systemd
				containerId = StringUtils.substringBetween(st, DOCKER_HYPHEN, SCOPE);
				if(StringUtils.isNotBlank(containerId)){
					return containerId;
				}
			}
		} catch (IOException e) {
			return null;
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
				if(isECSEnv) {
					identifier.setIsECSContainer(true);
					populateECSInfo(identifier);
				}
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
			identifier.setStartedAt(getStartedAt());
			applicationInfoBean.setIdentifier(identifier);
			return applicationInfoBean;
		} catch (Throwable e) {
			logger.log(LogLevel.WARNING, EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN, e,
					K2Instrumentator.class.getName());
		}
		return null;
	}
	
	private static Long getStartedAt() {
		try {
			ProcessBuilder processbuilder = new ProcessBuilder("/bin/sh", "-c", "date -d \"$(uptime -s)\" +%s");
			Process process = processbuilder.start();
			process.waitFor();
			String response = new String(IOUtils.readFully(process.getInputStream(), process.getInputStream().available()));
			return Long.parseLong(StringUtils.join(response.trim())) * 1000 ;
		} catch (Throwable e) {
			return Instant.now().toEpochMilli();
		}
	}

	private static void populateECSInfo(Identifier identifier) {
		identifier.setEcsTaskId(getECSTaskId());
		JSONObject ecsData = getECSInfo(identifier);
		if (ecsData != null) {
			String imageId = (String)ecsData.get("ImageID");
			if(imageId != null) {
				identifier.setImageId(imageId);
			}
			String imageName = (String)ecsData.get("Image");
			if(imageName != null) {
				identifier.setImageName(imageName);
			}
			JSONObject labels = (JSONObject)ecsData.get("Labels");
			if(labels != null) {
				String containerName = (String)labels.get("com.amazonaws.ecs.container-name");
				if(containerName != null) {
					identifier.setContainerName(containerName);
				}
				String ecsTaskDefinitionFamily = (String)labels.get("com.amazonaws.ecs.task-definition-family");
				String ecsTaskDefinitionVersion = (String)labels.get("com.amazonaws.ecs.task-definition-version");
				if(ecsTaskDefinitionFamily != null && ecsTaskDefinitionVersion != null) {
					identifier.setEcsTaskDefinition(ecsTaskDefinitionFamily + ":" + ecsTaskDefinitionVersion);
				}
			}
		}
	}
	
	private static JSONObject getECSInfo(Identifier identifier) {
		try {
			String url = System.getenv("ECS_CONTAINER_METADATA_URI");
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			String response = new String(IOUtils.readFully(httpClient.getInputStream(), httpClient.getInputStream().available()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject)parser.parse(response);
			return json;
		} catch (ParseException | IOException e) {
			return null;
		}
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
