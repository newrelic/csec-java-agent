package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;

public class VulnerableAPI {
	public static final String SEPARATOR_DOUBLE_COLON = "::";
	private String id;
	private String sourceMethod;
	private String userFileName;
	private String userMethodName;
	private String currentMethod;
	private Integer lineNumber;
	private JavaAgentEventBean causedByEvent;
	private boolean protectionEnabled = true;

	public VulnerableAPI(JavaAgentEventBean eventBean) {
		this.sourceMethod = eventBean.getSourceMethod();
		this.userFileName = eventBean.getUserFileName();
		this.userMethodName = eventBean.getUserMethodName();
		this.currentMethod = eventBean.getCurrentMethod();
		this.lineNumber = eventBean.getLineNumber();
		this.causedByEvent = eventBean;
		this.id = generateVulnerableAPIID(sourceMethod, userFileName, userMethodName, currentMethod, lineNumber);
	}

	public String getId() {
		return id;
	}

	public String getSourceMethod() {
		return sourceMethod;
	}

	public String getUserFileName() {
		return userFileName;
	}

	public String getUserMethodName() {
		return userMethodName;
	}

	public String getCurrentMethod() {
		return currentMethod;
	}

	public Integer getLineNumber() {
		return lineNumber;
	}

	public JavaAgentEventBean getCausedByEvent() {
		return causedByEvent;
	}

	public boolean isProtectionEnabled() {
		return protectionEnabled;
	}

	public void setProtectionEnabled(boolean protectionEnabled) {
		this.protectionEnabled = protectionEnabled;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);

	}

	public static String generateVulnerableAPIID(String sourceMethod, String userFileName,
												 String userMethodName, String currentMethod,
												 Integer lineNumber){
		return StringUtils.joinWith(SEPARATOR_DOUBLE_COLON, sourceMethod, userFileName, userMethodName, currentMethod, lineNumber);
	}

}
