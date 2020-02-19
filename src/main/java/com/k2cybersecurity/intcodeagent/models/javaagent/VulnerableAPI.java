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
	private Integer lineNumber;
	private boolean protectionEnabled = true;

	public VulnerableAPI(String sourceMethod, String userFileName, String userMethodName, Integer lineNumber) {
		this.sourceMethod = sourceMethod;
		this.userFileName = userFileName;
		this.userMethodName = userMethodName;
		this.lineNumber = lineNumber;
		this.id = generateVulnerableAPIID(sourceMethod, userFileName, userMethodName, lineNumber);
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

	public Integer getLineNumber() {
		return lineNumber;
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
												 String userMethodName,
												 Integer lineNumber){
		return StringUtils.joinWith(SEPARATOR_DOUBLE_COLON, sourceMethod, userFileName, userMethodName, lineNumber);
	}

}
