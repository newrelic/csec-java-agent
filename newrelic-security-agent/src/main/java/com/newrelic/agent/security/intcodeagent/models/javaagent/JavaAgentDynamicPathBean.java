package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

public class JavaAgentDynamicPathBean extends AgentBasicInfo {


    private String workingDirectory;

    private JSONArray jarPaths;

    private JSONArray dynamicPaths;

    public JavaAgentDynamicPathBean(String workingDirectory, JSONArray jarPaths, JSONArray dynamicPaths) {
        super();
        this.workingDirectory = workingDirectory;
        this.jarPaths = jarPaths;
        this.dynamicPaths = dynamicPaths;
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
