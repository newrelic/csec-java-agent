package com.k2cybersecurity.intcodeagent.models.javaagent;

public class ECSProperties extends EnvInfo {

    private String imageName;
    private String imageId;
    private String containerName;
    private String containerId;
    private String ecsTaskDefinition;
    private String ipAddress;
    private Long creationTimestamp;

    public ECSProperties() {
    }

    public String getImageName() {
        return imageName;
    }

    public void setImageName(String imageName) {
        this.imageName = imageName;
    }

    public String getImageId() {
        return imageId;
    }

    public void setImageId(String imageId) {
        this.imageId = imageId;
    }

    public String getContainerName() {
        return containerName;
    }

    public void setContainerName(String containerName) {
        this.containerName = containerName;
    }

    public String getContainerId() {
        return containerId;
    }

    public void setContainerId(String containerId) {
        this.containerId = containerId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Long getCreationTimestamp() {
        return creationTimestamp;
    }

    public void setCreationTimestamp(Long creationTimestamp) {
        this.creationTimestamp = creationTimestamp;
    }

    public String getEcsTaskDefinition() {
        return ecsTaskDefinition;
    }

    public void setEcsTaskDefinition(String ecsTaskDefinition) {
        this.ecsTaskDefinition = ecsTaskDefinition;
    }
}
