package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class HttpRequestBean {

	public static final String HTTP = "http";
	public static final String FORWARD_SLASH = "/";

	private String body;

	private String rawRequest;

	private Integer generationTime;

	private boolean dataTruncated;

	private String method;

	private String url;

	private String clientIP;

	private JSONObject headers;

	private Map<String, FileIntegrityBean> fileExist;

	private String contextPath;

	private String contentType;
	
	private String pathParams;

	private String protocol;

	@JsonIgnore
	private HttpResponseBean httpResponseBean;

	private int serverPort;

	private Map<String, String[]> parameterMap;
	
	private Map<String, String> pathParameterMap;

	private Collection parts;

	@JsonIgnore
	private Object servletContextObject;

	public HttpRequestBean() {
		this.rawRequest = StringUtils.EMPTY;
		this.clientIP = StringUtils.EMPTY;
		this.generationTime = 0;
		this.body = StringUtils.EMPTY;
		this.dataTruncated = false;
		this.method = StringUtils.EMPTY;
		this.url = StringUtils.EMPTY;
		this.headers = new JSONObject();
		this.fileExist = new HashMap<String, FileIntegrityBean>();
		this.contextPath = StringUtils.EMPTY;
		this.serverPort = -1;
		this.httpResponseBean = new HttpResponseBean();
		this.contentType = StringUtils.EMPTY;
		this.protocol = HTTP;
	}

	public HttpRequestBean(HttpRequestBean servletInfo) {
		this.rawRequest = new String(servletInfo.getRawRequest().trim());
		this.clientIP = new String(servletInfo.clientIP.trim());
		this.generationTime = servletInfo.getGenerationTime();
		this.body = new String(servletInfo.getBody().trim());
		this.dataTruncated = servletInfo.isDataTruncated();
		this.method = new String(servletInfo.getMethod().trim());
		this.url = new String(servletInfo.getUrl().trim());
		this.headers = new JSONObject(servletInfo.getHeaders());
		this.contextPath = new String(servletInfo.contextPath.trim());
		this.serverPort = servletInfo.serverPort;
		this.httpResponseBean = new HttpResponseBean(servletInfo.httpResponseBean);
		this.contentType = new String(servletInfo.contentType.trim());
		this.parameterMap = new HashMap<>(servletInfo.parameterMap);
		this.parts = servletInfo.parts;
		this.servletContextObject = servletInfo.servletContextObject;
		this.protocol = new String(servletInfo.protocol);
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

	public int getServerPort() {
		return serverPort;
	}

	public void setServerPort(int serverPort) {
		this.serverPort = serverPort;
	}

	public Map<String, String[]> getParameterMap() {
		return parameterMap;
	}

	public void setParameterMap(Map<String, String[]> parameterMap) {
		this.parameterMap = parameterMap;
	}

	public Collection getParts() {
		return parts;
	}

	public void setParts(Collection parts) {
		this.parts = parts;
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

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public void clearRawRequest() {
		this.rawRequest = StringUtils.EMPTY;
	}

	/**
	 * @return the clientIP
	 */
	public String getClientIP() {
		return clientIP;
	}

	/**
	 * @param clientIP the clientIP to set
	 */
	public void setClientIP(String clientIP) {
		this.clientIP = clientIP;
	}

	/**
	 * @return the fileAccessed
	 */
	public Map<String, FileIntegrityBean> getFileExist() {
		return fileExist;
	}

	/**
	 * @param fileAccessed the fileAccessed to set
	 */
	public void setFileExist(Map<String, FileIntegrityBean> fileAccessed) {
		this.fileExist = fileAccessed;
	}

	public String getContextPath() {
		return contextPath;
	}

	public void setContextPath(String contextPath) {
		if(StringUtils.isBlank(contextPath)) {
			this.contextPath = FORWARD_SLASH;
		} else {
			this.contextPath = contextPath;
		}
	}

	public void setBody(String body) {
		this.body = body;
	}

	@JsonIgnore
	public HttpResponseBean getHttpResponseBean() {
		return httpResponseBean;
	}

	@JsonIgnore
	public void setHttpResponseBean(HttpResponseBean httpResponseBean) {
		this.httpResponseBean = httpResponseBean;
	}

	public String getContentType() {
		return contentType;
	}

	public void setContentType(String contentType) {
		if(StringUtils.isNotBlank(contentType)) {
			this.contentType = StringUtils.substringBefore(contentType, ";").trim().toLowerCase();
		} else {
			this.contentType = StringUtils.EMPTY;
		}
	}

	public boolean isEmpty(){
		return StringUtils.isAnyBlank(url, method);
	}

	/**
	 * @return the pathParams
	 */
	public String getPathParams() {
		return pathParams;
	}

	/**
	 * @param pathParams the pathParams to set
	 */
	public void setPathParams(String pathParams) {
		this.pathParams = pathParams;
	}

	/**
	 * @return the pathParameterMap
	 */
	public Map<String, String> getPathParameterMap() {
		return pathParameterMap;
	}

	/**
	 * @param pathParameterMap the pathParameterMap to set
	 */
	public void setPathParameterMap(Map<String, String> pathParameterMap) {
		this.pathParameterMap = pathParameterMap;
	}

	public Object getServletContextObject() {
		return servletContextObject;
	}

	public void setServletContextObject(Object servletContextObject) {
		this.servletContextObject = servletContextObject;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

}


