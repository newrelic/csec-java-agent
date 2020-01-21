package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.io.File;

import org.apache.commons.lang3.StringUtils;

public class TrustBoundaryOperationalBean extends AbstractOperationalBean {

	private String key;
	private Object value;

	public TrustBoundaryOperationalBean(String key, Object value, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.key = key;
		this.value = value;
	}

	public TrustBoundaryOperationalBean(TrustBoundaryOperationalBean trustBoundaryOperationalBean) {
		super(trustBoundaryOperationalBean);
		this.key = trustBoundaryOperationalBean.key;
		this.value = trustBoundaryOperationalBean.value;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	/**
	 * @return the key
	 */
	public String getKey() {
		return key;
	}

	/**
	 * @param key the key to set
	 */
	public void setKey(String key) {
		this.key = key;
	}

	/**
	 * @return the value
	 */
	public Object getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(Object value) {
		this.value = value;
	}

	@Override
	public boolean isEmpty() {
		return StringUtils.isBlank(key);
	}

	


}
