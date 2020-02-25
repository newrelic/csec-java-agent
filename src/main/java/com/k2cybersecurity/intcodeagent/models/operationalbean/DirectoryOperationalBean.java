package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.io.File;

import org.apache.commons.lang3.StringUtils;

public class DirectoryOperationalBean extends AbstractOperationalBean {

	private String fileName;

	public DirectoryOperationalBean(String fileName, String className, String sourceMethod, String executionId,
			long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.fileName = fileName;
	}

	public DirectoryOperationalBean(DirectoryOperationalBean forkExecOperationalBean) {
		super(forkExecOperationalBean);
		this.fileName = forkExecOperationalBean.fileName;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	@Override
	public boolean isEmpty() {
		return StringUtils.isBlank(fileName);
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

}
