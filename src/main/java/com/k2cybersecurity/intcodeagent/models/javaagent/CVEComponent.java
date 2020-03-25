package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class CVEComponent {

	private String name;
	
	private String sha256;

	/**
	 * @param name
	 * @param sha256
	 */
	public CVEComponent(String name, String sha256) {
		super();
		this.name = name;
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
	
	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}
	
}
