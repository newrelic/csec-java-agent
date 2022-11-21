package com.newrelic.agent.security.intcodeagent.models.javaagent;

import java.util.List;

public class PodProperties extends EnvInfo {

    private String namespace;
    private String name;
    private String clusterName;
    private String clusterId;
    private String ipAddress;
    private String hostIpAddress;
    private Long creationTimestamp;

    private List<ContainerProperties> containerProperties;

    public PodProperties() {
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getClusterName() {
        return clusterName;
    }

    public void setClusterName(String clusterName) {
        this.clusterName = clusterName;
    }

    public String getClusterId() {
        return clusterId;
    }

    public void setClusterId(String clusterId) {
        this.clusterId = clusterId;
    }

    public List<ContainerProperties> getContainerProperties() {
        return containerProperties;
    }

    public void setContainerProperties(List<ContainerProperties> containerProperties) {
        this.containerProperties = containerProperties;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getHostIpAddress() {
        return hostIpAddress;
    }

    public void setHostIpAddress(String hostIpAddress) {
        this.hostIpAddress = hostIpAddress;
    }

    public Long getCreationTimestamp() {
        return creationTimestamp;
    }

    public void setCreationTimestamp(Long creationTimestamp) {
        this.creationTimestamp = creationTimestamp;
    }
}
