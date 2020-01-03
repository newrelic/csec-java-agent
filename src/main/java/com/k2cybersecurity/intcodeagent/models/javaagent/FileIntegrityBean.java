package com.k2cybersecurity.intcodeagent.models.javaagent;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;

public class FileIntegrityBean extends AbstractOperationalBean {

	private Boolean exists;
	private String userFileName;
	private String userMethodName;
	private String currentMethod;
	private Integer lineNumber;
	private String fileName;

	public FileIntegrityBean(String className, String sourceMethod, String executionId, Long startTime ) {
		super(className, sourceMethod, executionId, startTime);
	}
	
	public FileIntegrityBean(Boolean exists, String fileName, String className, String sourceMethod, String exectionId, Long startTime ) {
		this(className, sourceMethod, exectionId, startTime);
		this.exists = exists;
		this.setFileName(fileName);
	}

	
	/**
	 * @return the exists
	 */
	public Boolean getExists() {
		return exists;
	}

	/**
	 * @param exists the exists to set
	 */
	public void setExists(Boolean exists) {
		this.exists = exists;
	}

	/**
	 * @return the userFileName
	 */
	public String getUserFileName() {
		return userFileName;
	}

	/**
	 * @param userFileName the userFileName to set
	 */
	public void setUserFileName(String userFileName) {
		this.userFileName = userFileName;
	}

	/**
	 * @return the userMethodName
	 */
	public String getUserMethodName() {
		return userMethodName;
	}

	/**
	 * @param userMethodName the userMethodName to set
	 */
	public void setUserMethodName(String userMethodName) {
		this.userMethodName = userMethodName;
	}

	/**
	 * @return the currentMethod
	 */
	public String getCurrentMethod() {
		return currentMethod;
	}

	/**
	 * @param currentMethod the currentMethod to set
	 */
	public void setCurrentMethod(String currentMethod) {
		this.currentMethod = currentMethod;
	}

	/**
	 * @return the lineNumber
	 */
	public Integer getLineNumber() {
		return lineNumber;
	}

	/**
	 * @param lineNumber the lineNumber to set
	 */
	public void setLineNumber(Integer lineNumber) {
		this.lineNumber = lineNumber;
	}

	public void setBeanValues(String sourceMethod, String userFileName, String userMethodName, String currentMethod,
			Integer lineNumber) {
		this.setSourceMethod(sourceMethod);
		this.userFileName = userFileName;
		this.userMethodName = userMethodName;
		this.currentMethod = currentMethod;
		this.lineNumber = lineNumber;
	}

	@Override
	public boolean isEmpty() {
		return StringUtils.isBlank(fileName);
	}

	/**
	 * @return the fileName
	 */
	public String getFileName() {
		return fileName;
	}

	/**
	 * @param fileName the fileName to set
	 */
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
}
