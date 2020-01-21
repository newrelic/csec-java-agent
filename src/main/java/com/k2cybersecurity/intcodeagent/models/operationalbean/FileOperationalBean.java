package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.io.File;

import org.apache.commons.lang3.StringUtils;

public class FileOperationalBean extends AbstractOperationalBean {

	private String fileName;
	private boolean isExists;

	public FileOperationalBean(String fileName, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.fileName = fileName;
		this.isExists = new File(this.fileName).exists();
	}

	public FileOperationalBean(FileOperationalBean forkExecOperationalBean) {
		super(forkExecOperationalBean);
		this.fileName = forkExecOperationalBean.fileName;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	@Override public boolean isEmpty() {
		return StringUtils.isBlank(fileName);
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	/**
	 * @return the isExists
	 */
	public boolean isExists() {
		return isExists;
	}

	/**
	 * @param isExists the isExists to set
	 */
	public void setExists(boolean isExists) {
		this.isExists = isExists;
	}


}
