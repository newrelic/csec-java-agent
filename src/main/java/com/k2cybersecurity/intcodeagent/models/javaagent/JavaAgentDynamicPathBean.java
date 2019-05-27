package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JavaAgentDynamicPathBean extends AgentBasicInfo implements Serializable {

    /**
	 * 
	 */
	private static final long serialVersionUID = -2179815960689483454L;

	private String applicationUUID;

    private String workingDirectory;
    
    private List<String> jarPaths;
    
    private List<String> dynamicPaths;

    public JavaAgentDynamicPathBean(String applicationUUID,String workingDirectory, List<String> jarPaths,List<String> dynamicPaths) {
        super();
        this.applicationUUID = applicationUUID;
        this.workingDirectory = workingDirectory;
        this.jarPaths = jarPaths;
        this.dynamicPaths = dynamicPaths;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

	public String getWorkingDirectory() {
		return workingDirectory;
	}

	public void setWorkingDirectory(String workingDirectory) {
		this.workingDirectory = workingDirectory;
	}

	public List<String> getJarPaths() {
        return jarPaths;
    }

    public void setJarPaths(List<String> jarPaths) {
        this.jarPaths = jarPaths;
    }

    
    /**
	 * @return the dynamicPaths
	 */
	public List<String> getDynamicPaths() {
		return dynamicPaths;
	}

	/**
	 * @param dynamicPaths the dynamicPaths to set
	 */
	public void setDynamicPaths(List<String> dynamicPaths) {
		this.dynamicPaths = dynamicPaths;
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
