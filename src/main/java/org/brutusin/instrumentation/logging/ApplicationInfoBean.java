package org.brutusin.instrumentation.logging;

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
	
	public ApplicationInfoBean() {}
	
	public ApplicationInfoBean(Integer pid, String applicationUUID) {
	    super();
		this.pid = pid;
		this.applicationUUID = applicationUUID;
		this.startTime = System.currentTimeMillis();
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
	
}
