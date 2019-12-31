package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public abstract class AbstractOperationalBean {
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String className;

	private String sourceMethod;

	private String executionId;

	private long startTime;


	public AbstractOperationalBean(){
		this.className = StringUtils.EMPTY;
		this.sourceMethod = StringUtils.EMPTY;
		this.executionId = StringUtils.EMPTY;
		this.startTime = 0L;
	}

	public AbstractOperationalBean(AbstractOperationalBean abstractOperationalBean){
		this.className = abstractOperationalBean.className;
		this.sourceMethod = abstractOperationalBean.sourceMethod;
		this.executionId = abstractOperationalBean.executionId;
		this.startTime = abstractOperationalBean.startTime;
	}

	public AbstractOperationalBean(String className, String sourceMethod, String executionId, long startTime){
		this.className = className;
		this.sourceMethod = sourceMethod;
		this.executionId = executionId;
		this.startTime = startTime;
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

	public void setStartTime(long startTime) {
		this.startTime = startTime;
	}

	/**
	 * Logically determines if the bean is empty.
	 * @return boolean
	 */
	public abstract boolean isEmpty();
}
