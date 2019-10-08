package com.k2cybersecurity.intcodeagent.models.javaagent;

public class FileIntegrityBean {

	private Boolean exists;
	private String sourceMethod;
	private String userFileName;
	private String userMethodName;
	private String currentMethod;
	private Integer lineNumber;

	public FileIntegrityBean() {
	}
	
	public FileIntegrityBean(Boolean exists) {
		this.exists = exists;
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
	 * @return the sourceMethod
	 */
	public String getSourceMethod() {
		return sourceMethod;
	}

	/**
	 * @param sourceMethod the sourceMethod to set
	 */
	public void setSourceMethod(String sourceMethod) {
		this.sourceMethod = sourceMethod;
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
		this.sourceMethod = sourceMethod;
		this.userFileName = userFileName;
		this.userMethodName = userMethodName;
		this.currentMethod = currentMethod;
		this.lineNumber = lineNumber;
	}
}
