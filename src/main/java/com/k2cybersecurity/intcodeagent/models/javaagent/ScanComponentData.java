package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.util.List;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ScanComponentData extends AgentBasicInfo {

	private String applicationUUID;
	
	private List<CVEComponent> envComponents;
	
	private List<ApplicationScanComponentData> deployedApplications;

	public ScanComponentData() {
		super();
	}
	
	public ScanComponentData(String applicationUuid) {
		super();
		this.applicationUUID = applicationUuid;
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
	 * @return the envComponents
	 */
	public List<CVEComponent> getEnvComponents() {
		return envComponents;
	}

	/**
	 * @param envComponents the envComponents to set
	 */
	public void setEnvComponents(List<CVEComponent> envComponents) {
		this.envComponents = envComponents;
	}

	/**
	 * @return the deployedApplications
	 */
	public List<ApplicationScanComponentData> getDeployedApplications() {
		return deployedApplications;
	}

	/**
	 * @param deployedApplications the deployedApplications to set
	 */
	public void setDeployedApplications(List<ApplicationScanComponentData> deployedApplications) {
		this.deployedApplications = deployedApplications;
	}
	
	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}
}
