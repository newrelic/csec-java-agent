package com.k2cybersecurity.intcodeagent.models.operationalbean;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class SystemExitOperationalBean extends AbstractOperationalBean {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String exitCode;

	public SystemExitOperationalBean(String cmd, String className, String sourceMethod, String executionId,
			long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.exitCode = cmd;

	}

	public SystemExitOperationalBean(SystemExitOperationalBean systemExitOperationalBean) {
		super(systemExitOperationalBean);
		this.exitCode = systemExitOperationalBean.exitCode;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	@Override
	public boolean isEmpty() {
		return StringUtils.isBlank(exitCode);
	}

	public String getExitCode() {
		return exitCode;
	}

	public void setExitCode(String exitCode) {
		this.exitCode = exitCode;
	}
}
