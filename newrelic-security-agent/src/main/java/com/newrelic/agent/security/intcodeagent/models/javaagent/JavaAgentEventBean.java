package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.logging.DeployedApplication;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import org.json.simple.JSONArray;

import java.util.Arrays;

public class JavaAgentEventBean extends AgentBasicInfo {
    private Integer pid;
    private String applicationUUID;
    private Long startTime;
    private String sourceMethod;
    private String userFileName;
    private String userMethodName;
    private String currentMethod;
    private Boolean validationBypass;
    private Integer lineNumber;
    private JSONArray parameters;
    private Long eventGenerationTime;
    private HttpRequest httpRequest;
    private String id;
    private String parentId;
    private StackTraceElement[] stacktrace;
    private String caseType;
    private String eventCategory;
    private Long preProcessingTime;
    private AgentMetaData metaData;
    private Long blockingProcessingTime = 0L;

    private boolean isAPIBlocked = false;
    private boolean isIASTEnable = false;

    private boolean isIASTRequest = false;
    private String apiId;
    private DeployedApplication webappIdentifier;

    public JavaAgentEventBean() {
        super();
    }

    public void setUserAPIInfo(Integer lineNumber, String userClassName, String userMethodName) {
        this.userMethodName = userMethodName;
        this.userFileName = userClassName;
        this.lineNumber = lineNumber;
    }

    public JavaAgentEventBean(JavaAgentEventBean javaAgentEventBean) {
        this.pid = javaAgentEventBean.pid;
        this.applicationUUID = javaAgentEventBean.applicationUUID;
        this.startTime = javaAgentEventBean.startTime;
        this.sourceMethod = javaAgentEventBean.sourceMethod;
        this.userFileName = javaAgentEventBean.userFileName;
        this.userMethodName = javaAgentEventBean.userMethodName;
        this.currentMethod = javaAgentEventBean.currentMethod;
        this.validationBypass = javaAgentEventBean.validationBypass;
        this.lineNumber = javaAgentEventBean.lineNumber;
        this.eventGenerationTime = javaAgentEventBean.eventGenerationTime;
        this.httpRequest = new HttpRequest(javaAgentEventBean.httpRequest);
        this.id = javaAgentEventBean.id;
        this.parentId = javaAgentEventBean.parentId;
        this.stacktrace = Arrays.copyOf(javaAgentEventBean.stacktrace, javaAgentEventBean.stacktrace.length);
        this.caseType = javaAgentEventBean.caseType;
        this.eventCategory = javaAgentEventBean.eventCategory;
        this.preProcessingTime = javaAgentEventBean.preProcessingTime;
        this.metaData = new AgentMetaData(javaAgentEventBean.metaData);
        this.blockingProcessingTime = javaAgentEventBean.blockingProcessingTime;
        this.isAPIBlocked = javaAgentEventBean.isAPIBlocked;
        this.isIASTEnable = javaAgentEventBean.isIASTEnable;
        this.isIASTRequest = javaAgentEventBean.isIASTRequest;
        this.apiId = javaAgentEventBean.apiId;
        this.webappIdentifier = new DeployedApplication(javaAgentEventBean.webappIdentifier);
    }

    public Long getStartTime() {
        return startTime;
    }

    public void setStartTime(Long startTime) {
        this.startTime = startTime;
    }

    public String getSourceMethod() {
        return sourceMethod;
    }

    public void setSourceMethod(String sourceMethod) {
        this.sourceMethod = sourceMethod;
    }

    public String getUserFileName() {
        return userFileName;
    }

    public void setUserFileName(String userClassName) {
        this.userFileName = userClassName;
    }

    public String getUserMethodName() {
        return userMethodName;
    }

    public void setUserMethodName(String userMethodName) {
        this.userMethodName = userMethodName;
    }

    public Integer getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(Integer lineNumber) {
        this.lineNumber = lineNumber;
    }

    public JSONArray getParameters() {
        return parameters;
    }

    public void setParameters(JSONArray parameters) {
        this.parameters = parameters;
    }

    public Boolean getValidationBypass() {
        return validationBypass;
    }

    public void setValidationBypass(Boolean validationBypass) {
        this.validationBypass = validationBypass;
    }

    public boolean getIsIASTEnable() {
        return isIASTEnable;
    }

    public void setIsIASTEnable(boolean IASTEnable) {
        this.isIASTEnable = IASTEnable;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    /**
     * @return the pid
     */
    public Integer getPid() {
        return pid;
    }

    /**
     * @param pid the pid to set
     */
    public void setPid(Integer pid) {
        this.pid = pid;
    }

    /**
     * @return the currentMethod
     */
    public String getCurrentMethod() {
        return currentMethod;
    }

    /**
     * @param currentMethod the currentMethod to set
     */
    public void setCurrentMethod(String currentMethod) {
        this.currentMethod = currentMethod;
    }

    /**
     * @return the eventGenerationTime
     */
    public Long getEventGenerationTime() {
        return eventGenerationTime;
    }

    /**
     * @param eventGenerationTime the eventGenerationTime to set
     */
    public void setEventGenerationTime(Long eventGenerationTime) {
        this.eventGenerationTime = eventGenerationTime;
    }

    /**
     * @return the applicationUUID
     */
    public String getApplicationUUID() {
        return applicationUUID;
    }

    /**
     * @param applicationUUID the applicationUUID to set
     */
    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    /**
     * @return the servletInfo
     */
    public HttpRequest getHttpRequest() {
        return httpRequest;
    }

    /**
     * @param servletInfo the servletInfo to set
     */
    public void setHttpRequest(HttpRequest servletInfo) {
        this.httpRequest = servletInfo;
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return the stacktrace
     */
    public StackTraceElement[] getStacktrace() {
        return stacktrace;
    }

    /**
     * @param stacktrace the stacktrace to set
     */
    public void setStacktrace(StackTraceElement[] stacktrace) {
        this.stacktrace = stacktrace;
    }

    /**
     * @return the caseType
     */
    public String getCaseType() {
        return caseType;
    }

    /**
     * @param caseType the caseType to set
     */
    public void setCaseType(String caseType) {
        this.caseType = caseType;
    }

    /**
     * @return the preProcessingTime
     */
    public Long getPreProcessingTime() {
        return preProcessingTime;
    }

    /**
     * @param preProcessingTime the preProcessingTime to set
     */
    public void setPreProcessingTime(Long preProcessingTime) {
        this.preProcessingTime = preProcessingTime;
    }

    public AgentMetaData getMetaData() {
        return metaData;
    }

    public void setMetaData(AgentMetaData metaData) {
        this.metaData = metaData;
    }

    public String getEventCategory() {
        return eventCategory;
    }

    public void setEventCategory(String eventCategory) {
        this.eventCategory = eventCategory;
    }

    public Long getBlockingProcessingTime() {
        return blockingProcessingTime;
    }

    public void setBlockingProcessingTime(Long blockingProcessingTime) {
        this.blockingProcessingTime = blockingProcessingTime;
    }

    public boolean getIsAPIBlocked() {
        return isAPIBlocked;
    }

    public void setIsAPIBlocked(boolean APIBlocked) {
        this.isAPIBlocked = APIBlocked;
    }

    public String getApiId() {
        return apiId;
    }

    public void setApiId(String apiId) {
        this.apiId = apiId;
    }

    public DeployedApplication getWebappIdentifier() {
        return webappIdentifier;
    }

    public void setWebappIdentifier(DeployedApplication webappIdentifier) {
        this.webappIdentifier = webappIdentifier;
    }

    public boolean getIsIASTRequest() {
        return isIASTRequest;
    }

    public void setIsIASTRequest(boolean isIASTRequest) {
        this.isIASTRequest = isIASTRequest;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(String parentId) {
        this.parentId = parentId;
    }
}
