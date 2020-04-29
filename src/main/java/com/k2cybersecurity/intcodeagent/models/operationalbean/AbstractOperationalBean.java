package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPDoFilterMap;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

public abstract class AbstractOperationalBean {

	private String className;

	private String methodName;

	private String sourceMethod;

	private String executionId;

	private long startTime;

	private long blockingEndTime;

	private Object currentGenericServletInstance;

	private String currentGenericServletMethodName = StringUtils.EMPTY;

	private StackTraceElement[] stackTrace;

	private StackTraceElement userClassElement;

	private Boolean isCalledByUserCode;

	public AbstractOperationalBean(){
		this.className = StringUtils.EMPTY;
		this.sourceMethod = StringUtils.EMPTY;
		this.executionId = StringUtils.EMPTY;
		this.methodName = StringUtils.EMPTY;
		this.startTime = 0L;
		this.blockingEndTime = 0L;
		this.isCalledByUserCode = false;
	}

	public AbstractOperationalBean(String className, String sourceMethod, String executionId
			, long startTime, String methodName){
		this.className = className;
		this.sourceMethod = sourceMethod;
		this.executionId = executionId;
		this.startTime = startTime;
		this.methodName = methodName;
		this.blockingEndTime = 0L;
		this.currentGenericServletMethodName = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletMethodName();
		this.currentGenericServletInstance = ThreadLocalHTTPDoFilterMap.getInstance().getCurrentGenericServletInstance();
		this.stackTrace = Thread.currentThread().getStackTrace();
		Pair<Boolean, StackTraceElement> userClassDetectionResult = AgentUtils.getInstance().detectUserClass(this.stackTrace,
				this.currentGenericServletInstance,
				this.currentGenericServletMethodName, className, methodName);
		this.userClassElement = userClassDetectionResult.getRight();
		this.isCalledByUserCode = userClassDetectionResult.getLeft();
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

	public Object getCurrentGenericServletInstance() {
		return currentGenericServletInstance;
	}

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

	public StackTraceElement getUserClassElement() {
		return userClassElement;
	}

	public void setUserClassElement(StackTraceElement userClassElement) {
		this.userClassElement = userClassElement;
	}

	public String getMethodName() {
		return methodName;
	}

	public void setMethodName(String methodName) {
		this.methodName = methodName;
	}

	public Boolean getCalledByUserCode() {
		return isCalledByUserCode;
	}

	public void setCalledByUserCode(Boolean calledByUserCode) {
		isCalledByUserCode = calledByUserCode;
	}
}
