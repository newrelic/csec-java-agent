package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

public class JavaAgentDynamicPathBean extends AgentBasicInfo {

	private String applicationUUID;

    private String workingDirectory;
    
    private JSONArray jarPaths;
    
    private JSONArray dynamicPaths;

    public JavaAgentDynamicPathBean(String applicationUUID,String workingDirectory, JSONArray jarPaths,JSONArray dynamicPaths) {
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

	public JSONArray getJarPaths() {
        return jarPaths;
    }

    public void setJarPaths(JSONArray jarPaths) {
        this.jarPaths = jarPaths;
    }

    
    /**
	 * @return the dynamicPaths
	 */
	public JSONArray getDynamicPaths() {
		return dynamicPaths;
	}

	/**
	 * @param dynamicPaths the dynamicPaths to set
	 */
	public void setDynamicPaths(JSONArray dynamicPaths) {
		this.dynamicPaths = dynamicPaths;
	}

	@Override
    public String toString() {
		return JsonConverter.toJSON(this);
//        try {
//            return new ObjectMapper().writeValueAsString(this);
//        } catch (JsonProcessingException e) {
//            return null;
//        }
    }
}
