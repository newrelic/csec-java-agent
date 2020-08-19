package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class StartupProperties {

	private String logLevel;
	
	private String deploymentEnv;
	
	private FTPProperties ftpProperties;
	
	private boolean printHttpRequest;
	
	public StartupProperties() {
	}
	
	/**
	 * @param logLevel
	 * @param deploymentEnv
	 * @param enableFtp
	 * @param printHttpRequest
	 */
	public StartupProperties(String logLevel, String deploymentEnv, FTPProperties ftpProperties, boolean printHttpRequest) {
		super();
		this.logLevel = logLevel;
		this.deploymentEnv = deploymentEnv;
		this.ftpProperties = ftpProperties;
		this.printHttpRequest = printHttpRequest;
	}

	/**
	 * @return the logLevel
	 */
	public String getLogLevel() {
		return logLevel;
	}

	/**
	 * @param logLevel the logLevel to set
	 */
	public void setLogLevel(String logLevel) {
		this.logLevel = logLevel;
	}

	/**
	 * @return the deploymentEnv
	 */
	public String getDeploymentEnv() {
		return deploymentEnv;
	}

	/**
	 * @param deploymentEnv the deploymentEnv to set
	 */
	public void setDeploymentEnv(String deploymentEnv) {
		this.deploymentEnv = deploymentEnv;
	}

	/**
	 * @return the ftpProperties
	 */
	public FTPProperties getFtpProperties() {
		return ftpProperties;
	}

	/**
	 * @param ftpProperties the ftpProperties to set
	 */
	public void setFtpProperties(FTPProperties ftpProperties) {
		this.ftpProperties = ftpProperties;
	}

	/**
	 * @return the printHttpRequest
	 */
	public boolean isPrintHttpRequest() {
		return printHttpRequest;
	}

	/**
	 * @param printHttpRequest the printHttpRequest to set
	 */
	public void setPrintHttpRequest(boolean printHttpRequest) {
		this.printHttpRequest = printHttpRequest;
	}

	@Override
    public String toString() {
        return JsonConverter.toJSON(this);
	}
	
	
}
