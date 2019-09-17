package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import rawhttp.core.RawHttp;
import rawhttp.core.RawHttpRequest;

public class ServletInfo {

	private String body;

	private String rawRequest;

	private Integer generationTime;

	private boolean dataTruncated;

	private String method;

	private String url;

	private JSONObject headers;

	public ServletInfo() {
		this.generationTime = 0;
		this.body = IAgentConstants.EMPTY_STRING;
		this.dataTruncated = false;
		this.method = IAgentConstants.EMPTY_STRING;
		this.url = IAgentConstants.EMPTY_STRING;
		this.headers = new JSONObject();
	}

	public ServletInfo(ServletInfo servletInfo) {
		this.generationTime = servletInfo.getGenerationTime();
		this.body = servletInfo.getBody();
		this.dataTruncated = servletInfo.isDataTruncated();
		this.method = servletInfo.getMethod();
		this.url = servletInfo.getUrl();
		this.headers = new JSONObject(servletInfo.getHeaders());
		this.populateHttpRequest();
	}

	public String getRawRequest() {
		return rawRequest;
	}

	public void setRawRequest(String rawRequest) {
		this.rawRequest = rawRequest;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public JSONObject getHeaders() {
		return headers;
	}

	public void setHeaders(JSONObject headers) {
		this.headers = headers;
	}

	/**
	 * @return the body
	 */
	public String getBody() {
		return this.body;
	}

	/**
	 * @param body the body to set
	 */
	public void setBody(String body) {
		this.body = body;
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

	public void populateHttpRequest(){
		this.setRawRequest(StringEscapeUtils.unescapeJava(this.getRawRequest()));
		RawHttpRequest request = new RawHttp().parseRequest(this.rawRequest);

		this.setUrl(request.getUri().getRawPath() + "?" +request.getUri().getRawQuery());
		this.setMethod(request.getMethod());
		this.setHeaders(new JSONObject(request.getHeaders().asMap()));

		if (!this.isDataTruncated()) {
			try {
				this.setBody(StringUtils.substringAfter(rawRequest, "\r\n\r\n"));
			} catch (Exception e) {
				 e.printStackTrace();
			}
		}
		this.rawRequest = StringUtils.EMPTY;
	}
}
