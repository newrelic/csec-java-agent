package com.k2cybersecurity.intcodeagent.models.javaagent;

import org.apache.commons.text.StringEscapeUtils;

import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ServletInfo {

	private String rawRequest;

	private Integer generationTime;

	private boolean dataTruncated;

	public ServletInfo() {
		this.generationTime = 0;
		this.rawRequest = IAgentConstants.EMPTY_STRING;
		this.dataTruncated = false;
	}

	public ServletInfo(ServletInfo servletInfo) {
		this.generationTime = servletInfo.getGenerationTime();
		this.rawRequest = servletInfo.getRawRequest();
		this.dataTruncated = servletInfo.isDataTruncated();
	}

	/**
	 * @return the rawRequest
	 */
	public String getRawRequest() {
		return this.rawRequest;
	}

	/**
	 * @param rawRequest the rawRequest to set
	 */
	public void setRawRequest(String rawRequest) {
		this.rawRequest = StringEscapeUtils.escapeJava(rawRequest);
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	/**
	 * @return the dataTruncated
	 */
	public boolean isDataTruncated() {
		return this.dataTruncated;
	}

	/**
	 * @param dataTruncated the dataTruncated to set
	 */
	public void setDataTruncated(boolean dataTruncated) {
		this.dataTruncated = dataTruncated;
	}

	/**
	 * @return the generationTime
	 */
	public Integer getGenerationTime() {
		return generationTime;
	}

	/**
	 * @param generationTime the generationTime to set
	 */
	public void setGenerationTime(Integer generationTime) {
		this.generationTime = generationTime;
	}

	public Integer addGenerationTime(Integer time) {
		this.generationTime += time;
		return this.generationTime;
	}
}
