package com.newrelic.agent.security.schema;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class HttpRequest {
    public static final String HTTP = "http";

    private StringBuilder body;

    private boolean dataTruncated;

    private String method;

    private String url;

    private String clientIP;

    private String clientPort;

    private Map<String, String> headers;

    private String contentType;

    private String protocol;

    private int serverPort;

    private Map<String, String[]> parameterMap;

    private Map<String, String> pathParameterMap;

    private boolean isRequestParsed;

    public HttpRequest() {
        this.clientIP = StringUtils.EMPTY;
        this.body = new StringBuilder();
        this.dataTruncated = false;
        this.method = StringUtils.EMPTY;
        this.url = StringUtils.EMPTY;
        this.headers = new ConcurrentHashMap<>();
        this.serverPort = -1;
        this.contentType = StringUtils.EMPTY;
        this.protocol = HTTP;
        this.clientPort = StringUtils.EMPTY;
        this.parameterMap = new HashMap<>();
        this.isRequestParsed = false;
    }

    public HttpRequest(HttpRequest servletInfo) {
        this.clientIP = new String(servletInfo.clientIP.trim());
        this.body = new StringBuilder(servletInfo.getBody());
        this.dataTruncated = servletInfo.isDataTruncated();
        this.method = new String(servletInfo.getMethod().trim());
        this.url = new String(servletInfo.getUrl().trim());
        this.headers = new ConcurrentHashMap<>(servletInfo.getHeaders());
        this.serverPort = servletInfo.serverPort;
        this.contentType = new String(servletInfo.contentType.trim());
        this.parameterMap = new HashMap<>(servletInfo.parameterMap);
        this.protocol = new String(servletInfo.protocol);
        this.clientPort = new String(servletInfo.clientPort);
        this.isRequestParsed = servletInfo.isRequestParsed;
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

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    /**
     * @return the body
     */
    public StringBuilder getBody() {
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

    public void setBody(StringBuilder body) {
        this.body = body;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        if (StringUtils.isNotBlank(contentType)) {
            this.contentType = StringUtils.substringBefore(contentType, ";").trim().toLowerCase();
        } else {
            this.contentType = StringUtils.EMPTY;
        }
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(url, method);
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

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        if (StringUtils.isNotBlank(protocol)) {
            this.protocol = protocol;
        }
    }

    public String getClientPort() {
        return clientPort;
    }

    public void setClientPort(String clientPort) {
        this.clientPort = clientPort;
    }

    public boolean isRequestParsed() {
        return isRequestParsed;
    }

    public void setRequestParsed(boolean requestParsed) {
        isRequestParsed = requestParsed;
    }
}


