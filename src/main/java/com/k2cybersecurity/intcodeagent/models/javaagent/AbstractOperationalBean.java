package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public abstract class AbstractOperationalBean {
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String className;

	private String sourceMethod;

	private String executionId;

	public AbstractOperationalBean(){
		this.className = StringUtils.EMPTY;
		this.sourceMethod = StringUtils.EMPTY;
		this.executionId = StringUtils.EMPTY;
	}

	public AbstractOperationalBean(AbstractOperationalBean abstractOperationalBean){
		this.className = abstractOperationalBean.className;
		this.sourceMethod = abstractOperationalBean.sourceMethod;
		this.executionId = abstractOperationalBean.executionId;
	}

	public AbstractOperationalBean(String className, String sourceMethod, String executionId){
		this.className = className;
		this.sourceMethod = sourceMethod;
		this.executionId = executionId;
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
}
