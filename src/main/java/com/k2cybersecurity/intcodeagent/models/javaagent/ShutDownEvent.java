package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;
import java.util.List;

import com.google.gson.Gson;

public class ShutDownEvent extends AgentBasicInfo implements Serializable {

	private static final long serialVersionUID = -2320594688008671870L;
	
	private String applicationUUID;
	
	private String status;
	
	private List<String> resonForTermination;
	
	private Integer exitCode;

	public ShutDownEvent() {
		super();
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
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * @param status the status to set
	 */
	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * @return the resonForTermination
	 */
	public List<String> getResonForTermination() {
		return resonForTermination;
	}

	/**
	 * @param resonForTermination the resonForTermination to set
	 */
	public void setResonForTermination(List<String> resonForTermination) {
		this.resonForTermination = resonForTermination;
	}

	/**
	 * @return the exitCode
	 */
	public Integer getExitCode() {
		return exitCode;
	}

	/**
	 * @param exitCode the exitCode to set
	 */
	public void setExitCode(Integer exitCode) {
		this.exitCode = exitCode;
	}
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

}
