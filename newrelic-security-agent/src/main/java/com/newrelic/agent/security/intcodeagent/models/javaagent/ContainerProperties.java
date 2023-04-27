package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

@JsonInclude(value = JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ContainerProperties extends EnvInfo {

    private String name;

    private Boolean isPrivileged;

    private String imageId;

    private String imageName;

    private String entrypoint;

    private Long creationTimestamp;

    private Map portBindings;

    private List mounts;

    private String state;

    private List<String> capAdd;

    private List<String> capDrop;

    private Float cpuUsage;

    private String ipAddress;

    public ContainerProperties() {
    }

    public ContainerProperties(String containerId) {
        super(containerId);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean isPrivileged() {
        return isPrivileged;
    }

    public void setPrivileged(Boolean privileged) {
        isPrivileged = privileged;
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

    public String getEntrypoint() {
        return entrypoint;
    }

    public void setEntrypoint(String entrypoint) {
        this.entrypoint = entrypoint;
    }

    public Long getCreationTimestamp() {
        return creationTimestamp;
    }

    public void setCreationTimestamp(Long creationTimestamp) {
        this.creationTimestamp = creationTimestamp;
    }

    public Map getPortBindings() {
        return portBindings;
    }

    public void setPortBindings(Map portBindings) {
        this.portBindings = portBindings;
    }

    public List getMounts() {
        return mounts;
    }

    public void setMounts(List mounts) {
        this.mounts = mounts;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public List getCapAdd() {
        return capAdd;
    }

    public void setCapAdd(List capAdd) {
        this.capAdd = capAdd;
    }

    public List getCapDrop() {
        return capDrop;
    }

    public void setCapDrop(List capDrop) {
        this.capDrop = capDrop;
    }

    public Float getCpuUsage() {
        return cpuUsage;
    }

    public void setCpuUsage(Float cpuUsage) {
        this.cpuUsage = cpuUsage;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

}
