package org.brutusin.instrumentation.logging;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.brutusin.com.fasterxml.jackson.core.JsonProcessingException;
import org.brutusin.com.fasterxml.jackson.databind.ObjectMapper;

public class ServletInfo implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5693096693182224287L;

	private String queryString;

	private String sourceIp;

	private String requestMethod;

	private String rawParameters;

	private String contentType;

	private String requestURI;

	/**
	 * @return the requestURI
	 */
	public String getRequestURI() {
		return requestURI;
	}

	/**
	 * @param requestURI
	 *            the requestURI to set
	 */
	public void setRequestURI(String requestURI) {
		this.requestURI = requestURI;
	}

	public ServletInfo() {
	}

	public ServletInfo(ServletInfo servletInfo) {
		this.queryString = servletInfo.getQueryString();
		this.sourceIp = servletInfo.getSourceIp();
		this.requestMethod = servletInfo.getRequestMethod();
		this.rawParameters = servletInfo.getRawParameters();
		this.contentType = servletInfo.getContentType();
		this.requestURI = servletInfo.getRequestURI();
	}

	/**
	 * @return the rawParameters
	 */
	public String getRawParameters() {
		return rawParameters;
	}

	/**
	 * @param rawParameters
	 *            the rawParameters to set
	 */
	public void setRawParameters(String rawParameters) {
		this.rawParameters = rawParameters;
	}

	/**
	 * @return the contentType
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * @param contentType
	 *            the contentType to set
	 */
	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

	/**
	 * @return the queryString
	 */
	public String getQueryString() {
		return queryString;
	}

	/**
	 * @param queryString
	 *            the queryString to set
	 */
	public void setQueryString(String queryString) {
		this.queryString = queryString;
	}

	/**
	 * @return the sourceIp
	 */
	public String getSourceIp() {
		return sourceIp;
	}

	/**
	 * @param sourceIp
	 *            the sourceIp to set
	 */
	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}

	/**
	 * @return the requestMethod
	 */
	public String getRequestMethod() {
		return requestMethod;
	}

	/**
	 * @param requestMethod
	 *            the requestMethod to set
	 */
	public void setRequestMethod(String requestMethod) {
		this.requestMethod = requestMethod;
	}

	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
	}
}
