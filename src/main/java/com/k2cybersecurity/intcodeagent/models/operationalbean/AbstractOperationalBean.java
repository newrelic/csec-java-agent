package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPDoFilterMap;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.UserClassEntity;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public abstract class AbstractOperationalBean {

    private String className;

    private String methodName;

    private String sourceMethod;

    private String executionId;

    private long startTime;

    private long blockingEndTime;

    @JsonIgnore
    private Object currentGenericServletInstance;

    private String currentGenericServletMethodName = StringUtils.EMPTY;

    private StackTraceElement[] stackTrace;

    private UserClassEntity userClassEntity;

    private String apiID;

    public AbstractOperationalBean() {
        this.className = StringUtils.EMPTY;
        this.sourceMethod = StringUtils.EMPTY;
        this.executionId = StringUtils.EMPTY;
        this.methodName = StringUtils.EMPTY;
        this.startTime = 0L;
        this.blockingEndTime = 0L;
        this.apiID = StringUtils.EMPTY;
    }

    public AbstractOperationalBean(String className, String sourceMethod, String executionId
            , long startTime, String methodName) {
        this.className = className;
        this.sourceMethod = sourceMethod;
        this.executionId = executionId;
        this.startTime = startTime;
        this.methodName = methodName;
        this.blockingEndTime = 0L;
        this.currentGenericServletMethodName = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletMethodName();
        this.currentGenericServletInstance = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletInstance();
        this.stackTrace = Thread.currentThread().getStackTrace();
        this.userClassEntity = AgentUtils.getInstance().detectUserClass(this.stackTrace,
                this.currentGenericServletInstance,
                this.currentGenericServletMethodName, className, methodName);


    }

    public String toString() {
        return JsonConverter.toJSON(this);
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

    @JsonIgnore
    public Object getCurrentGenericServletInstance() {
        return currentGenericServletInstance;
    }

    @JsonIgnore
    public void setCurrentGenericServletInstance(Object currentGenericServletInstance) {
        this.currentGenericServletInstance = currentGenericServletInstance;
    }

    public String getCurrentGenericServletMethodName() {
        return currentGenericServletMethodName;
    }

    public void setCurrentGenericServletMethodName(String currentGenericServletMethodName) {
        this.currentGenericServletMethodName = currentGenericServletMethodName;
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
}
