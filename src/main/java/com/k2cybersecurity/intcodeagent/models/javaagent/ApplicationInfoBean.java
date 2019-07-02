package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;

import org.json.simple.JSONArray;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ApplicationInfoBean extends AgentBasicInfo implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = -4692519856531306026L;
	
	private Integer pid;
	private String applicationName;
	private Boolean isHost;
	private String containerID;
	private JSONArray jvmArguments;
	private Long startTime;
	private String applicationUUID;
	private String javaCommand;
	private String classPath;
	private String userDir;
	private String libraryPath;
	private String bootLibraryPath;
	private String javaRuntimeName;
	private String javaRuntimeVersion;
	private String osArch;
	private String osName;
	private String osVersion;

	/**
	 * @return the libraryPath
	 */
	public String getLibraryPath() {
		return libraryPath;
	}

	/**
	 * @param libraryPath the libraryPath to set
	 */
	public void setLibraryPath(String libraryPath) {
		this.libraryPath = libraryPath;
	}

	/**
	 * @return the bootLibraryPath
	 */
	public String getBootLibraryPath() {
		return bootLibraryPath;
	}

	/**
	 * @param bootLibraryPath the bootLibraryPath to set
	 */
	public void setBootLibraryPath(String bootLibraryPath) {
		this.bootLibraryPath = bootLibraryPath;
	}

	/**
	 * @return the javaRuntimeName
	 */
	public String getJavaRuntimeName() {
		return javaRuntimeName;
	}

	/**
	 * @param javaRuntimeName the javaRuntimeName to set
	 */
	public void setJavaRuntimeName(String javaRuntimeName) {
		this.javaRuntimeName = javaRuntimeName;
	}

	/**
	 * @return the javaRuntimeVersion
	 */
	public String getJavaRuntimeVersion() {
		return javaRuntimeVersion;
	}

	/**
	 * @param javaRuntimeVersion the javaRuntimeVersion to set
	 */
	public void setJavaRuntimeVersion(String javaRuntimeVersion) {
		this.javaRuntimeVersion = javaRuntimeVersion;
	}

	/**
	 * @return the osArch
	 */
	public String getOsArch() {
		return osArch;
	}

	/**
	 * @param osArch the osArch to set
	 */
	public void setOsArch(String osArch) {
		this.osArch = osArch;
	}

	/**
	 * @return the osName
	 */
	public String getOsName() {
		return osName;
	}

	/**
	 * @param osName the osName to set
	 */
	public void setOsName(String osName) {
		this.osName = osName;
	}

	/**
	 * @return the osVersion
	 */
	public String getOsVersion() {
		return osVersion;
	}

	/**
	 * @param osVersion the osVersion to set
	 */
	public void setOsVersion(String osVersion) {
		this.osVersion = osVersion;
	}

	
	public ApplicationInfoBean() {}
	
	public ApplicationInfoBean(Integer pid, String applicationUUID) {
	    super();
		this.pid = pid;
		this.applicationUUID = applicationUUID;
		this.javaCommand = System.getProperty("sun.java.command");
		this.classPath = System.getProperty("java.class.path");
		this.userDir = System.getProperty("user.dir");
		this.libraryPath=System.getProperty("java.library.path");
		this.bootLibraryPath=System.getProperty("sun.boot.library.path");
		this.javaRuntimeName=System.getProperty("java.runtime.name");
		this.javaRuntimeVersion=System.getProperty("java.runtime.version");
		this.osArch=System.getProperty("os.arch");
		this.osName=System.getProperty("os.name");
		this.osVersion=System.getProperty("os.version");
	}
	/**
	 * @return the pid
	 */
	public Integer getPid() {
		return pid;
	}
	/**
	 * @param pid the pid to set
	 */
	public void setPid(Integer pid) {
		this.pid = pid;
	}
	/**
	 * @return the jvmArguments
	 */
	public JSONArray getJvmArguments() {
		return jvmArguments;
	}
	/**
	 * @param jvmArguments the jvmArguments to set
	 */
	public void setJvmArguments(JSONArray jvmArguments) {
		this.jvmArguments = jvmArguments;
	}
	
	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
	}
	/**
	 * @return the startTime
	 */
	public Long getStartTime() {
		return startTime;
	}
	/**
	 * @param startTime the startTime to set
	 */
	public void setStartTime(Long startTime) {
		this.startTime = startTime;
	}

	/**
	 * @return the applicationName
	 */
	public String getApplicationName() {
		return applicationName;
	}

	/**
	 * @param applicationName the applicationName to set
	 */
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	/**
	 * @return the applicationUUID
	 */
	public String getApplicationUUID() {
		return applicationUUID;
	}

	/**
	 * @param applicationUUID the applicationUUID to set
	 */
	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
	}
	
	/**
	 * @return the containerID
	 */
	public String getContainerID() {
		return containerID;
	}

	/**
	 * @param containerID the containerID to set
	 */
	public void setContainerID(String containerID) {
		this.containerID = containerID;
	}

	/**
	 * @return the isHost
	 */
	public Boolean getIsHost() {
		return isHost;
	}

	/**
	 * @param isHost the isHost to set
	 */
	public void setIsHost(Boolean isHost) {
		this.isHost = isHost;
	}

	public String getClassPath() {
		return classPath;
	}

	public void setClassPath(String classPath) {
		this.classPath = classPath;
	}

	public String getJavaCommand() {
		return javaCommand;
	}

	public void setJavaCommand(String javaCommand) {
		this.javaCommand = javaCommand;
	}

	/**
	 * @return the userDir
	 */
	public String getUserDir() {
		return userDir;
	}

	/**
	 * @param userDir the userDir to set
	 */
	public void setUserDir(String userDir) {
		this.userDir = userDir;
	}
	
}
