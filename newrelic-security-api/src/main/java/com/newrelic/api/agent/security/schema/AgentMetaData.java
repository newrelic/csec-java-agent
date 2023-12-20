package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AgentMetaData {

    private boolean triggerViaRCI;

    private boolean triggerViaDeserialisation;

    private boolean triggerViaXXE;

    private boolean isClientDetectedFromXFF;

    private Set<String> rciMethodsCalls;

    @JsonIgnore
    private boolean apiBlocked = false;

    private Map<String, String> userDataTranslationMap;

    private Map<String, String> reflectedMetaData;

    @JsonIgnore
    private StackTraceElement[] serviceTrace;

    @JsonIgnore
    private boolean userLevelServiceMethodEncountered = false;

    @JsonIgnore
    private String userLevelServiceMethodEncounteredFramework;

    @JsonIgnore
    private Set<String> ips;

    public AgentMetaData() {
        this.rciMethodsCalls = new HashSet<>();
        this.ips = new HashSet<>();
        this.userDataTranslationMap = new HashMap<>();
        this.reflectedMetaData = new HashMap<>();
    }

    public AgentMetaData(AgentMetaData agentMetaData) {
        this.rciMethodsCalls = new HashSet<>();
        this.rciMethodsCalls.addAll(agentMetaData.rciMethodsCalls);
        this.triggerViaDeserialisation = agentMetaData.triggerViaDeserialisation;
        this.triggerViaRCI = agentMetaData.triggerViaRCI;
        this.isClientDetectedFromXFF = agentMetaData.isClientDetectedFromXFF;
        this.serviceTrace = agentMetaData.serviceTrace;
        this.ips = new HashSet<>(agentMetaData.ips);
        this.apiBlocked = agentMetaData.apiBlocked;
        this.userDataTranslationMap = new HashMap<>(agentMetaData.userDataTranslationMap);
        this.userLevelServiceMethodEncountered = agentMetaData.userLevelServiceMethodEncountered;
        this.reflectedMetaData = agentMetaData.reflectedMetaData;
    }

    public boolean isTriggerViaRCI() {
        return triggerViaRCI;
    }

    public void setTriggerViaRCI(boolean triggerViaRCI) {
        this.triggerViaRCI = triggerViaRCI;
    }

    public boolean isTriggerViaDeserialisation() {
        return triggerViaDeserialisation;
    }

    public void setTriggerViaDeserialisation(boolean triggerViaDeserialisation) {
        this.triggerViaDeserialisation = triggerViaDeserialisation;
    }

    public boolean isTriggerViaXXE() {
        return triggerViaXXE;
    }

    public void setTriggerViaXXE(boolean triggerViaXXE) {
        this.triggerViaXXE = triggerViaXXE;
    }

    public Set<String> getRciMethodsCalls() {
        return rciMethodsCalls;
    }

    public void setRciMethodsCalls(Set<String> rciMethodsCalls) {
        this.rciMethodsCalls = rciMethodsCalls;
    }

    public boolean isClientDetectedFromXFF() {
        return isClientDetectedFromXFF;
    }

    public void setClientDetectedFromXFF(boolean clientDetectedFromXFF) {
        isClientDetectedFromXFF = clientDetectedFromXFF;
    }

    public Map<String, String> getReflectedMetaData() {
        return reflectedMetaData;
    }

    public void setReflectedMetaData(Map<String, String> reflectedMetaData) {
        this.reflectedMetaData = reflectedMetaData;
    }

    public void addReflectedMetaData(String metaKey, String metaData) {
        if(this.reflectedMetaData==null) {
            this.reflectedMetaData = new HashMap<>();
        }
        this.reflectedMetaData.put(metaKey, metaData);
    }

    public StackTraceElement[] getServiceTrace() {
        return serviceTrace;
    }

    public void setServiceTrace(StackTraceElement[] serviceTrace) {
        this.serviceTrace = serviceTrace;
    }

    public Set<String> getIps() {
        return ips;
    }

    public void setIps(Set<String> ips) {
        this.ips = ips;
    }

    public boolean isApiBlocked() {
        return apiBlocked;
    }

    public void setApiBlocked(boolean apiBlocked) {
        this.apiBlocked = apiBlocked;
    }

    public Map<String, String> getUserDataTranslationMap() {
        return userDataTranslationMap;
    }

    public void setUserDataTranslationMap(Map<String, String> userDataTranslationMap) {
        this.userDataTranslationMap = userDataTranslationMap;
    }

    public boolean isUserLevelServiceMethodEncountered() {
        return userLevelServiceMethodEncountered;
    }

    public boolean isUserLevelServiceMethodEncountered(String framework) {
        return userLevelServiceMethodEncountered &&
                StringUtils.equals(userLevelServiceMethodEncounteredFramework, framework);
    }

    public void setUserLevelServiceMethodEncountered(boolean userLevelServiceMethodEncountered) {
        this.userLevelServiceMethodEncountered = userLevelServiceMethodEncountered;
    }
}
