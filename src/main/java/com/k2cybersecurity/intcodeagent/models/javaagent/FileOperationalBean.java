package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class FileOperationalBean extends AbstractOperationalBean {

	private String fileName;

	public FileOperationalBean(String fileName, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.fileName = fileName;
	}

	public FileOperationalBean(FileOperationalBean forkExecOperationalBean) {
		super(forkExecOperationalBean);
		this.fileName = forkExecOperationalBean.fileName;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}


}
