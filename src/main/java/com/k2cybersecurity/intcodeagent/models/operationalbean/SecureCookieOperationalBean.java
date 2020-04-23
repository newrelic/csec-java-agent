package com.k2cybersecurity.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

public class SecureCookieOperationalBean extends AbstractOperationalBean {
	private String value;

	public SecureCookieOperationalBean(String value, String className, String sourceMethod, String executionId,
			long startTime, String methodName) {
		super(className, sourceMethod, executionId, startTime, methodName);
		this.value = value;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	@Override
	public boolean isEmpty() {
		return StringUtils.isBlank(value);
	}

}
