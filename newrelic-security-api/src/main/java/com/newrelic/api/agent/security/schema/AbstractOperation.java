package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.NewRelicSecurity;

import java.util.Map;

public abstract class AbstractOperation {

    public static final String EMPTY = "";
    private String className;

    private String methodName;

    private String sourceMethod;

    private String executionId;

    private long startTime;

    private long blockingEndTime;

    private StackTraceElement[] stackTrace;

    private UserClassEntity userClassEntity;

    private String apiID;

    private VulnerabilityCaseType caseType;

    private boolean isLowSeverityHook;

    private DeserializationInfo deserializationInfo;

    public AbstractOperation() {
        this.className = EMPTY;
        this.sourceMethod = EMPTY;
        this.executionId = EMPTY;
        this.methodName = EMPTY;
        this.startTime = 0L;
        this.blockingEndTime = 0L;
        this.apiID = EMPTY;
    }

    public AbstractOperation(String className, String methodName){
            this.className = className;
            this.methodName = methodName;
            this.blockingEndTime = 0L;
            if (NewRelicSecurity.getAgent() != null &&
                    NewRelicSecurity.getAgent().getSecurityMetaData() != null &&
                    NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializingObjectStack() != null) {
                this.deserializationInfo = NewRelicSecurity.getAgent().getSecurityMetaData()
                        .peekDeserializingObjectStack();
                this.deserializationInfo.computeObjectMap();
            }
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getSourceMethod() {
        return sourceMethod;
    }

    public void setSourceMethod(String sourceMethod) {
        this.sourceMethod = sourceMethod;
    }

    public String getExecutionId() {
        return executionId;
    }

    public void setExecutionId(String executionId) {
        this.executionId = executionId;
    }

    public long getStartTime() {
        return startTime;
    }

    /**
     * Logically determines if the bean is empty.
     *
     * @return boolean
     */
    public abstract boolean isEmpty();

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getBlockingEndTime() {
        return blockingEndTime;
    }

    public void setBlockingEndTime(long blockingEndTime) {
        this.blockingEndTime = blockingEndTime;
    }

    public StackTraceElement[] getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.stackTrace = stackTrace;
    }

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public UserClassEntity getUserClassEntity() {
        return userClassEntity;
    }

    public void setUserClassEntity(UserClassEntity userClassEntity) {
        this.userClassEntity = userClassEntity;
    }

    public String getApiID() {
        return apiID;
    }

    public void setApiID(String apiID) {
        this.apiID = apiID;
    }

    public VulnerabilityCaseType getCaseType() {
        return caseType;
    }

    public void setCaseType(VulnerabilityCaseType caseType) {
        this.caseType = caseType;
    }

    public boolean isLowSeverityHook() {
        return isLowSeverityHook;
    }

    public void setLowSeverityHook(boolean lowSeverityHook) {
        this.isLowSeverityHook = lowSeverityHook;
    }

    public DeserializationInfo getDeserializationInfo() {
        return deserializationInfo;
    }

    public void setDeserializationInfo(DeserializationInfo deserializationInfo) {
        this.deserializationInfo = deserializationInfo;
    }
}
