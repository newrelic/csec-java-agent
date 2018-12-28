package org.brutusin.instrumentation.logging;

import org.brutusin.com.fasterxml.jackson.core.JsonProcessingException;
import org.brutusin.com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class JarPathBean extends AgentBasicInfo {

    private String applicationUUID;

    private List<String> jarPaths;

    public JarPathBean(String applicationUUID, List<String> jarPaths) {
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

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
