package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ForkExecOperationalBean extends AbstractOperationalBean{

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String command;

	private Map<String,String> environment;


	public ForkExecOperationalBean(String[] cmd, Map<String,String> environment, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.command = StringUtils.join(cmd, StringUtils.SPACE);
		if(environment != null) {
			this.environment = new HashMap<>(environment);
		}

	}

	public ForkExecOperationalBean(ForkExecOperationalBean forkExecOperationalBean) {
		super(forkExecOperationalBean);
		this.command = forkExecOperationalBean.command;
		if(forkExecOperationalBean.environment != null) {
			this.environment = new HashMap<>(forkExecOperationalBean.environment);
		}
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
	}

}
