package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class HttpRequestBean {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String GOT_EMPTY_COMPONENT_LIST_FROM_RAW_REQUEST = "Got empty component list from raw request.";
	public static final String UNABLE_TO_EXTRACT_THE_REQUEST_LINE = "Unable to extract the request line.";
	public static final String GOT_EMPTY_MAP_AFTER_EXTRACTING_THE_HEADERS = "Got empty map after extracting the headers.";
	public static final String GOT_EMPTY_BODY_AFTER_PROCESSING = "Got empty body after processing";
	public static final String DOUBLE_NL_SEPARATOR = "\n\n";
	public static final String DOUBLE_CR_SEPARATOR = "\r\n\r\n";
	public static final String ERROR_WHILE_PROCESSING_HEADERS = "Error while processing headers : ";
	public static final String COLON_SEPARATOR_CHAR = ":";
	public static final String ERROR_WHILE_PROCESSING_REQUEST_LINE = "Error while processing request line : ";
	public static final String INVALID_REQUEST_LINE_MISSING_MANDATORY_COMPONENTS = "Invalid request line. Missing mandatory components : ";
	public static final String CR_OR_NL_SEPARATOR = "\n";

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

	@JsonIgnore
	private HttpResponseBean httpResponseBean;

	private int serverPort;

	public HttpRequestBean() {
		this.rawRequest = StringUtils.EMPTY;
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
	}

	public HttpRequestBean(HttpRequestBean servletInfo) {
		this.rawRequest = servletInfo.getRawRequest();
		this.clientIP = servletInfo.clientIP;
		this.generationTime = servletInfo.getGenerationTime();
		this.body = servletInfo.getBody();
		this.dataTruncated = servletInfo.isDataTruncated();
		this.method = servletInfo.getMethod();
		this.url = servletInfo.getUrl();
		this.headers = new JSONObject(servletInfo.getHeaders());
		this.contextPath = servletInfo.contextPath;
		this.serverPort = servletInfo.serverPort;
		this.httpResponseBean = servletInfo.httpResponseBean;
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
	//	/**
//	 * @param body the body to set
//	 */
//	public void setBody(String body) {
//		this.body = body;
//	}

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

	public String[] splitRequestComponents() {
		return StringUtils.splitPreserveAllTokens(this.rawRequest, CR_OR_NL_SEPARATOR);
	}

	public boolean parseRequestLineFromRawRequest(String[] components) {
		try {
			String requestLine = components[0];
			String[] requestLineComponents = StringUtils.split(requestLine);
			if (requestLineComponents.length >= 1) {
				this.method = requestLineComponents[0];
				this.url = requestLineComponents[1];
			} else {
				logger.log(LogLevel.ERROR,
						INVALID_REQUEST_LINE_MISSING_MANDATORY_COMPONENTS + Arrays.asList(requestLineComponents), this.getClass().getName());
				return false;
			}
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR_WHILE_PROCESSING_REQUEST_LINE + this.rawRequest, this.getClass().getName());
			return false;
		}
		return true;
	}

	public boolean parseHeadersFromRawRequest(String[] components) {
		this.headers = new JSONObject();
		try {
			for (int i = 1; i < components.length; i++) {
				String currentLine = components[i];
//				System.out.println("Current line : " + currentLine);
				if (StringUtils.isBlank(currentLine)){
//					System.out.println("Breaking out");
					break;
				}
				String[] currentComponents = new String[] {StringUtils.substringBefore(currentLine, COLON_SEPARATOR_CHAR),StringUtils.substringAfter(currentLine, COLON_SEPARATOR_CHAR)};
				if (currentComponents.length > 1 && StringUtils.isNoneBlank(currentComponents)) {
					this.headers.put(currentComponents[0].trim(), currentComponents[1].trim());
				}
			}
			return this.headers.size() > 0;
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR_WHILE_PROCESSING_HEADERS + this.rawRequest, this.getClass().getName());
			return false;
		}
	}

	public boolean parseBodyFromRawRequest() {
		this.body = StringUtils.substringAfter(this.rawRequest, DOUBLE_CR_SEPARATOR);
		if (StringUtils.isEmpty(this.body)){
			this.body = StringUtils.substringAfter(this.rawRequest, DOUBLE_NL_SEPARATOR);
		}
		this.body = StringEscapeUtils.escapeJava(this.body);
		return this.body.length() > 0;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public void clearRawRequest() {
		this.rawRequest = StringUtils.EMPTY;
	}

	public void populateHttpRequest() {
//		this.setRawRequest(StringEscapeUtils.unescapeJava(this.getRawRequest()));
		String[] components = splitRequestComponents();
		if (components == null || components.length == 0) {
			logger.log(LogLevel.ERROR, GOT_EMPTY_COMPONENT_LIST_FROM_RAW_REQUEST, this.getClass().getName());
			return;
		}
//		System.err.println("\n\nComponents : " + Arrays.asList(components));
		if (!parseRequestLineFromRawRequest(components)) {
			logger.log(LogLevel.ERROR, UNABLE_TO_EXTRACT_THE_REQUEST_LINE, this.getClass().getName());
			return;
		}

		if (!parseHeadersFromRawRequest(components)) {
			logger.log(LogLevel.ERROR, GOT_EMPTY_MAP_AFTER_EXTRACTING_THE_HEADERS, this.getClass().getName());
			return;
		}

		if (!parseBodyFromRawRequest()) {
			logger.log(LogLevel.DEBUG, GOT_EMPTY_BODY_AFTER_PROCESSING, this.getClass().getName());
		}
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

//	public static void main(String[] args) {
//		HttpRequestBean servletInfo = new HttpRequestBean();
//		String raw = "GET /DemoApplication-0.0.1-SNAPSHOT/UserCheck?user=test&password=1%27+OR+2*3%3D5%2B1+%23 HTTP/1.1\r\nhost:localhost:8080\r\nconnection:keep-alive\r\nupgrade-insecure-requests:1\r\nuser-agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36\r\naccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nreferer:http://localhost:8080/DemoApplication-0.0.1-SNAPSHOT/sample1.jsp\r\naccept-encoding:gzip, deflate\r\naccept-language:en-US,en;q=0.9\r\ncookie:JSESSIONID=887548369E69A897729666A6F33728FE; SESSION=vgbbsmq400gl1qpnjnsqo0qdjm; JSESSIONID=908DCB5F35DEE838AE85E3DD8E6B5176\r\n";
//
////		String raw = "POST /codeijc HTTP/1.1\r\nhost:localhost:8080\r\nconnection:keep-alive\r\ncache-control:max-age=0\r\norigin:http://localhost:8080\r\nupgrade-insecure-requests:1\r\ncontent-type:application/x-www-form-urlencoded\r\nuser-agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36\r\naccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nreferer:http://localhost:8080/codeijc\r\naccept-encoding:gzip, deflate\r\naccept-language:en-GB,en-US;q=0.9,en;q=0.8\r\ncookie:JSESSIONID=AA03FD28F4C5B568C2C22589E1F747C3\r\ncontent-length:88\r\n\r\njsonString=%7B%7D%27%29%3Bjava.lang.Runtime.getRuntime%28%29.exec%28%22ls%22%29%3B%2F%2F";
//		servletInfo.setRawRequest(raw);
//		servletInfo.populateHttpRequest();
//		System.out.println(servletInfo);
//	}

	public String getContextPath() {
		return contextPath;
	}

	public void setContextPath(String contextPath) {
		this.contextPath = contextPath;
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

	public boolean isEmpty(){
		return StringUtils.isAnyBlank(url, method);
	}
}
