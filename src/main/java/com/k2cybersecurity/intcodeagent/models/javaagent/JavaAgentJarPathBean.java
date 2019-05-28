package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JavaAgentJarPathBean extends AgentBasicInfo implements Serializable{

    /**
	 * 
	 */
	private static final long serialVersionUID = -4616871472044555920L;

	private String applicationUUID;

    private List<String> jarPaths;
    
    private Boolean isHost;

    public JavaAgentJarPathBean(String applicationUUID, List<String> jarPaths) {
        super();
        this.applicationUUID = applicationUUID;
        this.jarPaths = jarPaths;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public List<String> getJarPaths() {
        return jarPaths;
    }

    public void setJarPaths(List<String> jarPaths) {
        this.jarPaths = jarPaths;
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

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
