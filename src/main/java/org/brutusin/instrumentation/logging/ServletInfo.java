package org.brutusin.instrumentation.logging;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public class ServletInfo implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5693096693182224287L;

	private Map<String, String[]> parameters;
	
	private String queryString;
	
	private String sourceIp;
	
	private String requestMethod;

	/**
	 * @return the queryString
	 */
	public String getQueryString() {
		return queryString;
	}

	/**
	 * @param queryString the queryString to set
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
	 * @param sourceIp the sourceIp to set
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
	 * @param requestMethod the requestMethod to set
	 */
	public void setRequestMethod(String requestMethod) {
		this.requestMethod = requestMethod;
	}

	/**
	 * @return the parameters
	 */
	public Map<String, String[]> getParameters() {
		return parameters;
	}

	/**
	 * @param parameters the parameters to set
	 */
	public void setParameters(Map<String, String[]> parameters) {
		this.parameters = parameters;
	}
	
}
