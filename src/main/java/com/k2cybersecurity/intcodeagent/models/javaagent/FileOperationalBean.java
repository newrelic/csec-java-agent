package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class FileOperationalBean {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String fileName;

	public FileOperationalBean(String fileName) {
		this.fileName = fileName;
	}

	public FileOperationalBean(FileOperationalBean forkExecOperationalBean) {
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
