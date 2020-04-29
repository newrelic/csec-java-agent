package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class SSRFOperationalBean extends AbstractOperationalBean{

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private Object[] apiCallArgs;

	public SSRFOperationalBean(Object[] apiCallArgs, String className, String sourceMethod, String executionId, long startTime, String methodName) {
		super(className, sourceMethod, executionId, startTime, methodName);
		this.apiCallArgs = apiCallArgs;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	@Override public boolean isEmpty() {
		return apiCallArgs == null || apiCallArgs.length <= 0 ;
	}

	public Object[] getApiCallArgs() {
		return apiCallArgs;
	}

	public void setApiCallArgs(Object[] apiCallArgs) {
		this.apiCallArgs = apiCallArgs;
	}
}

