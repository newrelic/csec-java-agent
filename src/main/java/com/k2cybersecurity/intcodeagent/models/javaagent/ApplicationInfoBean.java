package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.logging.ServerInfo;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

import java.util.Arrays;

public class ApplicationInfoBean extends AgentBasicInfo {

	/** The sha 256. */
	private String sha256;
	
	/** pid of process. */
	private Integer pid;
	
	private String ipaddress;

	/** UUID per running application. */
	private String applicationUUID;

	/** Is application running on host. */
	private Boolean isHost;

	/** The container ID of running application. */
	private String containerID;

	/** name of running application. */
	private String applicationName;

	/** cmdline. */
	private String cmdline;

	/** application start time. */
	private Long startTime;

	private String runCommand;

	private String procStartTime;

	private String userDir;
	private JSONArray libraryPath;
	private String bootLibraryPath;
	private String binaryName;
	private String binaryVersion;
	private String osArch;
	private String osName;
	private String osVersion;
	
	private String binaryPath;

	private String agentAttachmentType;

	private ServerInfo serverInfo;

	public ApplicationInfoBean(Integer pid, String applicationUUID, String agentAttachmentType) {
		super();
		this.pid = pid;
		this.applicationUUID = applicationUUID;
		this.runCommand = System.getProperty("sun.java.command");
		this.userDir = System.getProperty("user.dir");
		this.libraryPath = new JSONArray();
		this.libraryPath.addAll(Arrays.asList(System.getProperty("java.library.path").split(":")));
		this.libraryPath.addAll(Arrays.asList(System.getProperty("java.class.path").split(":")));
		this.bootLibraryPath = System.getProperty("sun.boot.library.path");
		this.binaryVersion = System.getProperty("java.runtime.version");
		this.osArch = System.getProperty("os.arch");
		this.osName = System.getProperty("os.name");
		this.osVersion = System.getProperty("os.version");
		this.agentAttachmentType = agentAttachmentType;
		this.serverInfo = new ServerInfo();
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
//		try {
//			return new ObjectMapper().writeValueAsString(this);
//		} catch (JsonProcessingException e) {
//			return null;
//		}
	}

	public Integer getPid() {
		return pid;
	}

	public void setPid(Integer pid) {
		this.pid = pid;
	}

	public String getApplicationUUID() {
		return applicationUUID;
	}

	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
	}

	public Boolean getIsHost() {
		return isHost;
	}

	public void setIsHost(Boolean host) {
		isHost = host;
	}

	public String getContainerID() {
		return containerID;
	}

	public void setContainerID(String containerID) {
		this.containerID = containerID;
	}

	public String getApplicationName() {
		return applicationName;
	}

	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	public String getCmdline() {
		return cmdline;
	}

	public void setCmdline(String cmdline) {
		this.cmdline = cmdline;
	}

	public Long getStartTime() {
		return startTime;
	}

	public void setStartTime(Long startTime) {
		this.startTime = startTime;
	}

	public String getRunCommand() {
		return runCommand;
	}

	public void setRunCommand(String runCommand) {
		this.runCommand = runCommand;
	}

	public String getProcStartTime() {
		return procStartTime;
	}

	public void setProcStartTime(String procStartTime) {
		this.procStartTime = procStartTime;
	}

	public String getUserDir() {
		return userDir;
	}

	public void setUserDir(String userDir) {
		this.userDir = userDir;
	}

	public JSONArray getLibraryPath() {
		return libraryPath;
	}

	public void setLibraryPath(JSONArray libraryPath) {
		this.libraryPath = libraryPath;
	}

	public String getBootLibraryPath() {
		return bootLibraryPath;
	}

	public void setBootLibraryPath(String bootLibraryPath) {
		this.bootLibraryPath = bootLibraryPath;
	}

	public String getBinaryName() {
		return binaryName;
	}

	public void setBinaryName(String binaryName) {
		this.binaryName = binaryName;
	}

	public String getBinaryVersion() {
		return binaryVersion;
	}

	public void setBinaryVersion(String binaryVersion) {
		this.binaryVersion = binaryVersion;
	}

	public String getOsArch() {
		return osArch;
	}

	public void setOsArch(String osArch) {
		this.osArch = osArch;
	}

	public String getOsName() {
		return osName;
	}

	public void setOsName(String osName) {
		this.osName = osName;
	}

	public String getOsVersion() {
		return osVersion;
	}

	public void setOsVersion(String osVersion) {
		this.osVersion = osVersion;
	}

	public String getAgentAttachmentType() {
		return agentAttachmentType;
	}

	public void setAgentAttachmentType(String agentAttachmentType) {
		this.agentAttachmentType = agentAttachmentType;
	}

	public ServerInfo getServerInfo() {
		return serverInfo;
	}

	public void setServerInfo(ServerInfo serverInfo) {
		this.serverInfo = serverInfo;
	}

	/**
	 * @return the binaryPath
	 */
	public String getBinaryPath() {
		return binaryPath;
	}

	/**
	 * @param binaryPath the binaryPath to set
	 */
	public void setBinaryPath(String binaryPath) {
		this.binaryPath = binaryPath;
	}

	/**
	 * @return the sha256
	 */
	public String getSha256() {
		return sha256;
	}

	/**
	 * @param sha256 the sha256 to set
	 */
	public void setSha256(String sha256) {
		this.sha256 = sha256;
	}

	/**
	 * @return the ipaddress
	 */
	public String getIpaddress() {
		return ipaddress;
	}

	/**
	 * @param ipaddress the ipaddress to set
	 */
	public void setIpaddress(String ipaddress) {
		this.ipaddress = ipaddress;
	}
}
