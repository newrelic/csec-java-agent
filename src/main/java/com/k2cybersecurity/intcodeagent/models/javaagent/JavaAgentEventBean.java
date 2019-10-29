package com.k2cybersecurity.intcodeagent.models.javaagent;

import org.json.simple.JSONArray;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class JavaAgentEventBean extends AgentBasicInfo {
	private Integer pid;
	private String applicationUUID;
	private Long startTime;
	private String sourceMethod;
	private String userFileName;
	private String userMethodName;
	private String currentMethod;
	private Boolean validationBypass;
	private Integer lineNumber;
	private JSONArray parameters;
	private Long eventGenerationTime;
	private HttpRequestBean httpRequest;
	private String id;
	private JSONArray stacktrace;
	private String caseType;
	private Long preProcessingTime;
	private boolean rciElement;

	public JavaAgentEventBean() {
		super();
	}

	public JavaAgentEventBean(Long startTime, Long preProcessingTime, String sourceMethod, Integer pid,
							  String applicationUUID, String id, VulnerabilityCaseType vulnerabilityCaseType) {
		this.id = id;
		this.setPid(pid);
		this.applicationUUID = applicationUUID;
		this.sourceMethod = sourceMethod;
		this.startTime = startTime;
		this.setCaseType(vulnerabilityCaseType.getCaseType());
		this.setPreProcessingTime(preProcessingTime);
	}

	public JavaAgentEventBean(Long startTime, String sourceMethod, JSONArray parameters, Integer pid, String applicationUUID,
							  String id, VulnerabilityCaseType vulnerabilityCaseType) {
		this.id = id;
		this.setPid(pid);
		this.applicationUUID = applicationUUID;
		this.sourceMethod = sourceMethod;
		this.parameters = parameters;
		this.startTime = startTime;
		this.setCaseType(vulnerabilityCaseType.getCaseType());
	}

	public void setUserAPIInfo(Integer lineNumber, String userClassName, String userMethodName) {
		this.userMethodName = userMethodName;
		this.userFileName = userClassName;
		this.lineNumber = lineNumber;
	}

	public Long getStartTime() {
		return startTime;
	}

	public void setStartTime(Long startTime) {
		this.startTime = startTime;
	}

	public String getSourceMethod() {
		return sourceMethod;
	}

	public void setSourceMethod(String sourceMethod) {
		this.sourceMethod = sourceMethod;
	}

	public String getUserFileName() {
		return userFileName;
	}

	public void setUserFileName(String userClassName) {
		this.userFileName = userClassName;
	}

	public String getUserMethodName() {
		return userMethodName;
	}

	public void setUserMethodName(String userMethodName) {
		this.userMethodName = userMethodName;
	}

	public Integer getLineNumber() {
		return lineNumber;
	}

	public void setLineNumber(Integer lineNumber) {
		this.lineNumber = lineNumber;
	}

	public JSONArray getParameters() {
		return parameters;
	}

	public void setParameters(JSONArray parameters) {
		this.parameters = parameters;
	}

	public Boolean getValidationBypass() {
		return validationBypass;
	}

	public void setValidationBypass(Boolean validationBypass) {
		this.validationBypass = validationBypass;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);

	}

	/**
	 * @return the pid
	 */
	public Integer getPid() {
		return pid;
	}

	/**
	 * @param pid the pid to set
	 */
	public void setPid(Integer pid) {
		this.pid = pid;
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
	 * @return the eventGenerationTime
	 */
	public Long getEventGenerationTime() {
		return eventGenerationTime;
	}

	/**
	 * @param eventGenerationTime the eventGenerationTime to set
	 */
	public void setEventGenerationTime(Long eventGenerationTime) {
		this.eventGenerationTime = eventGenerationTime;
	}

	/**
	 * @return the applicationUUID
	 */
	public String getApplicationUUID() {
		return applicationUUID;
	}

	/**
	 * @param applicationUUID the applicationUUID to set
	 */
	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
	}

	/**
	 * @return the servletInfo
	 */
	public HttpRequestBean getHttpRequest() {
		return httpRequest;
	}

	/**
	 * @param servletInfo the servletInfo to set
	 */
	public void setHttpRequest(HttpRequestBean servletInfo) {
		this.httpRequest = servletInfo;
	}

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * @return the stacktrace
	 */
	public JSONArray getStacktrace() {
		return stacktrace;
	}

	/**
	 * @param stacktrace the stacktrace to set
	 */
	public void setStacktrace(JSONArray stacktrace) {
		this.stacktrace = stacktrace;
	}

	/**
	 * @return the caseType
	 */
	public String getCaseType() {
		return caseType;
	}

	/**
	 * @param caseType the caseType to set
	 */
	public void setCaseType(String caseType) {
		this.caseType = caseType;
	}

	/**
	 * @return the preProcessingTime
	 */
	public Long getPreProcessingTime() {
		return preProcessingTime;
	}

	/**
	 * @param preProcessingTime the preProcessingTime to set
	 */
	public void setPreProcessingTime(Long preProcessingTime) {
		this.preProcessingTime = preProcessingTime;
	}

	/**
	 * @return the rciElement
	 */
	public boolean getRciElement() {
		return rciElement;
	}

	/**
	 * @param rciElement the rciElement to set
	 */
	public void setRciElement(boolean rciElement) {
		this.rciElement = rciElement;
	}

}
