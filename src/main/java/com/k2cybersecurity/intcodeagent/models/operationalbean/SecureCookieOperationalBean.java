package com.k2cybersecurity.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

public class SecureCookieOperationalBean extends AbstractOperationalBean {
	private String value;

	public SecureCookieOperationalBean(String value, String className, String sourceMethod, String executionId,
			long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.value = value;
	}

	public SecureCookieOperationalBean(AbstractOperationalBean abstractOperationalBean) {
		super(abstractOperationalBean);
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
