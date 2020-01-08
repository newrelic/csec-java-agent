package com.k2cybersecurity.intcodeagent.models.operationalbean;

public class SecureCookieOperationalBean extends AbstractOperationalBean {
	private boolean value;

	public SecureCookieOperationalBean(Boolean value, String className, String sourceMethod, String executionId,
			long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.value = value;
	}

	public SecureCookieOperationalBean(AbstractOperationalBean abstractOperationalBean) {
		super(abstractOperationalBean);
	}

	public boolean getValue() {
		return value;
	}

	public void setValue(boolean value) {
		this.value = value;
	}

	@Override
	public boolean isEmpty() {
		return false;
	}

}
