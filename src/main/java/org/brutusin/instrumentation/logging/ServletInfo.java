package org.brutusin.instrumentation.logging;

import java.io.Serializable;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ServletInfo implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5693096693182224287L;

	private String rawRequest;
	
	private boolean dataTruncated;
	
	private String sourceIp;

	public ServletInfo() {
		this.rawRequest = "";
		this.dataTruncated = false;
	}


	public ServletInfo(ServletInfo servletInfo) {
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
	 * @param rawRequest
	 *            the rawRequest to set
	 */
	public void setRawRequest(String rawRequest) {
		this.rawRequest = rawRequest;
	}

	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
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
	 * @return the sourceIp
	 */
	public String getSourceIp() {
		return sourceIp;
	}


	/**
	 * @param sourceIp the sourceIp to set
	 */
	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}
}
