/**
 * 
 */
package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

/**
 * @author lovesh
 *
 */
public class Identifier {

	private String ipaddress;

	private Boolean isHost = false;

	private Boolean isContainer = false;

	private Boolean isPod = false;

	private String containerId;

	private String podId;

	private String namespace;

	private String hostname;

	private String ecsTaskId;

	private String containerName;

	private String imageId;

	private String imageName;

	private String startedAt;
	
	private String ecsTaskDefinition;

	public String getEcsTaskDefinition() {
		return ecsTaskDefinition;
	}

	public void setEcsTaskDefinition(String ecsTaskDefinition) {
		this.ecsTaskDefinition = ecsTaskDefinition;
	}

	/**
	 * @param ipaddress
	 */
	public Identifier(String ipaddress) {
		super();
		this.ipaddress = ipaddress;
	}

	public String getIpaddress() {
		return ipaddress;
	}

	public void setIpaddress(String ipaddress) {
		this.ipaddress = ipaddress;
	}

	public Boolean getIsHost() {
		return isHost;
	}

	public void setIsHost(Boolean isHost) {
		this.isHost = isHost;
	}

	public Boolean getIsContainer() {
		return isContainer;
	}

	public void setIsContainer(Boolean isContainer) {
		this.isContainer = isContainer;
	}

	public Boolean getIsPod() {
		return isPod;
	}

	public void setIsPod(Boolean isPod) {
		this.isPod = isPod;
	}

	public String getContainerId() {
		return containerId;
	}

	public void setContainerId(String containerId) {
		this.containerId = containerId;
	}

	public String getPodId() {
		return podId;
	}

	public void setPodId(String podId) {
		this.podId = podId;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	/**
	 * @return the namespace
	 */
	public String getNamespace() {
		return namespace;
	}

	/**
	 * @param namespace the namespace to set
	 */
	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}

	/**
	 * @return the hostname
	 */
	public String getHostname() {
		return hostname;
	}

	/**
	 * @param hostname the hostname to set
	 */
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getEcsTaskId() {
		return ecsTaskId;
	}

	public void setEcsTaskId(String ecsTaskId) {
		this.ecsTaskId = ecsTaskId;
	}

	public String getContainerName() {
		return containerName;
	}

	public void setContainerName(String containerName) {
		this.containerName = containerName;
	}

	public String getImageId() {
		return imageId;
	}

	public void setImageId(String imageId) {
		this.imageId = imageId;
	}

	public String getImageName() {
		return imageName;
	}

	public void setImageName(String imageName) {
		this.imageName = imageName;
	}

	public String getStartedAt() {
		return startedAt;
	}

	public void setStartedAt(String startedAt) {
		this.startedAt = startedAt;
	}

}
