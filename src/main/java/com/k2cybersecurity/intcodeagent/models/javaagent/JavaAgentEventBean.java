package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;
import java.util.List;

import org.json.simple.JSONArray;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;


public class JavaAgentEventBean extends AgentBasicInfo implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = -6572256624089364532L;
	private Integer pid;
	private String applicationUUID;
	private Long startTime;
	private String source;
	private String userClassName;
	private String userMethodName;
	private String currentMethod;
	private boolean validationBypass;
	private Integer lineNumber;
	private JSONArray parameters;
	private Long eventGenerationTime;
	private ServletInfo servletInfo;
	private String id;
	private List<TraceElement> stacktrace;
	private String caseType;
	private Long preProcessingTime;

	public JavaAgentEventBean() {
	    super();
	}
	
	public JavaAgentEventBean(Long startTime, Long preProcessingTime, String source, Integer pid, String applicationUUID, String id, VulnerabilityCaseType vulnerabilityCaseType) {
	    this.id = id;
		this.setPid(pid);
		this.applicationUUID = applicationUUID;
		this.source = source;
		this.startTime = startTime;
		this.setCaseType(vulnerabilityCaseType.getCaseType());
		this.setPreProcessingTime(preProcessingTime);
	}
	
	public JavaAgentEventBean(Long startTime, String source, JSONArray parameters, Integer pid, String applicationUUID, String id, VulnerabilityCaseType vulnerabilityCaseType) {
	    this.id = id;
		this.setPid(pid);
		this.applicationUUID = applicationUUID;
		this.source = source;
		this.parameters = parameters;
		this.startTime = startTime;
		this.setCaseType(vulnerabilityCaseType.getCaseType());
	}

	public void setUserAPIInfo(Integer lineNumber, String userClassName, String userMethodName) {
		this.userMethodName = userMethodName;
		this.userClassName = userClassName;
		this.lineNumber = lineNumber;
	}

	public Long getStartTime() {
		return startTime;
	}

	public void setStartTime(Long startTime) {
		this.startTime = startTime;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public String getUserClassName() {
		return userClassName;
	}

	public void setUserClassName(String userClassName) {
		this.userClassName = userClassName;
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

	public boolean getValidationBypass() { return validationBypass;	}

	public void setValidationBypass(boolean validationBypass) { this.validationBypass = validationBypass; }


	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
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
	public ServletInfo getServletInfo() {
		return servletInfo;
	}

	/**
	 * @param servletInfo the servletInfo to set
	 */
	public void setServletInfo(ServletInfo servletInfo) {
		this.servletInfo = servletInfo;
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
	public List<TraceElement> getStacktrace() {
		return stacktrace;
	}

	/**
	 * @param stacktrace the stacktrace to set
	 */
	public void setStacktrace(List<TraceElement> stacktrace) {
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

}
