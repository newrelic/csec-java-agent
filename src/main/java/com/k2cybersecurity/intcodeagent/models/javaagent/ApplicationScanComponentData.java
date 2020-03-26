package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.util.Set;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ApplicationScanComponentData {

	private String name;
	
	private String sha256;
	
	private Set<CVEComponent> components;

	public ApplicationScanComponentData(String appName, String sha256) {
		this.name = appName;
		this.sha256 = sha256;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
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
	 * @return the components
	 */
	public Set<CVEComponent> getComponents() {
		return components;
	}

	/**
	 * @param components the components to set
	 */
	public void setComponents(Set<CVEComponent> components) {
		this.components = components;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}
	
}
