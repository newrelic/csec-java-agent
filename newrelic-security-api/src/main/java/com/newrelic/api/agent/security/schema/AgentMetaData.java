package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;
import com.newrelic.api.agent.security.schema.policy.SkipScanParameters;

import java.util.*;

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

    private SkipScanParameters skipScanParameters;

    @JsonIgnore
    private StackTraceElement[] serviceTrace;

    @JsonIgnore
    private boolean userLevelServiceMethodEncountered = false;

    @JsonIgnore
    private String userLevelServiceMethodEncounteredFramework;

    @JsonIgnore
    private int fromJumpRequiredInStackTrace = 2;

    @JsonIgnore
    private boolean foundAnnotedUserLevelServiceMethod = false;

    @JsonIgnore
    private String framework;

    @JsonIgnore
    private Set<String> ips;

    private AppServerInfo appServerInfo;

    public AgentMetaData() {
        this.rciMethodsCalls = new HashSet<>();
        this.ips = new HashSet<>();
        this.userDataTranslationMap = new HashMap<>();
        this.reflectedMetaData = new HashMap<>();
        this.appServerInfo = new AppServerInfo();
        this.framework = StringUtils.EMPTY;
        this.skipScanParameters = new SkipScanParameters();
    }

    public AgentMetaData(AgentMetaData agentMetaData) {
        this.rciMethodsCalls = new HashSet<>();
        agentMetaData.rciMethodsCalls.remove(null);
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
        this.appServerInfo = agentMetaData.appServerInfo;
        this.triggerViaXXE = agentMetaData.triggerViaXXE;
        this.userLevelServiceMethodEncounteredFramework = agentMetaData.userLevelServiceMethodEncounteredFramework;
        this.foundAnnotedUserLevelServiceMethod = agentMetaData.foundAnnotedUserLevelServiceMethod;
        this.fromJumpRequiredInStackTrace = agentMetaData.getFromJumpRequiredInStackTrace();
        this.framework = agentMetaData.framework;
        this.skipScanParameters = agentMetaData.skipScanParameters;
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

    public String getUserLevelServiceMethodEncounteredFramework() {
        return userLevelServiceMethodEncounteredFramework;
    }

    public void setUserLevelServiceMethodEncounteredFramework(String userLevelServiceMethodEncounteredFramework) {
        this.userLevelServiceMethodEncounteredFramework = userLevelServiceMethodEncounteredFramework;
    }

    public AppServerInfo getAppServerInfo() {
        return appServerInfo;
    }

    public void setAppServerInfo(AppServerInfo appServerInfo) {
        this.appServerInfo = appServerInfo;
    }

    public int getFromJumpRequiredInStackTrace() {
        return fromJumpRequiredInStackTrace;
    }

    public void setFromJumpRequiredInStackTrace(int fromJumpRequiredInStackTrace) {
        this.fromJumpRequiredInStackTrace = fromJumpRequiredInStackTrace;
    }
    public boolean isFoundAnnotedUserLevelServiceMethod() {
        return foundAnnotedUserLevelServiceMethod;
    }

    public void setFoundAnnotedUserLevelServiceMethod(boolean foundAnnotedUserLevelServiceMethod) {
        this.foundAnnotedUserLevelServiceMethod = foundAnnotedUserLevelServiceMethod;
    }

    public String getFramework() {
        return framework;
    }

    public void setFramework(Framework framework) {
        if (StringUtils.isEmpty(this.framework) || StringUtils.equals(this.framework, Framework.SERVLET.name())) {
            this.framework = framework.name();
        }
    }

    public SkipScanParameters getSkipScanParameters() {
        return skipScanParameters;
    }

    public void setSkipScanParameters(SkipScanParameters skipScanParameters) {
        this.skipScanParameters = skipScanParameters;
    }
}
