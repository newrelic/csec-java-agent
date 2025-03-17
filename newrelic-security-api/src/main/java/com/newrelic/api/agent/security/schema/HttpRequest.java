package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.StringBuilderLimit;
import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class HttpRequest {
    public static final String HTTP = "http";

    @JsonIgnore
    public static final String QUESTION_MARK = "?";

    private final StringBuilderLimit body;

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

    private boolean isGrpc;

    private String route;
    private String requestURI;

    private final Map<String, String> customDataType;

    @JsonIgnore
    private Set<String> pathParameters;

    @JsonIgnore
    private Map<String, Set<String>> queryParameters;

    @JsonIgnore
    private Map<String, Set<String>> requestHeaderParameters;

    @JsonIgnore
    private Map<String, Set<String>> requestBodyParameters;

    @JsonIgnore
    private boolean isRequestParametersParsed = false;

    public HttpRequest() {
        this.clientIP = StringUtils.EMPTY;
        this.body = new StringBuilderLimit();
        this.method = StringUtils.EMPTY;
        this.url = StringUtils.EMPTY;
        this.headers = new ConcurrentHashMap<>();
        this.serverPort = -1;
        this.contentType = StringUtils.EMPTY;
        this.protocol = HTTP;
        this.clientPort = StringUtils.EMPTY;
        this.parameterMap = new HashMap<>();
        this.isRequestParsed = false;
        this.isGrpc = false;
        this.route = StringUtils.EMPTY;
        this.requestURI = StringUtils.EMPTY;
        this.customDataType = new HashMap<>();
        this.pathParameterMap = new HashMap<>();
        this.queryParameters = new HashMap<>();
        this.requestHeaderParameters = new HashMap<>();
        this.requestBodyParameters = new HashMap<>();
    }

    public HttpRequest(HttpRequest servletInfo) {
        this.clientIP = servletInfo.clientIP.trim();
        this.body = servletInfo.body;
        this.method = servletInfo.getMethod().trim();
        this.url = servletInfo.getUrl().trim();
        this.headers = new ConcurrentHashMap<>(servletInfo.getHeaders());
        this.serverPort = servletInfo.serverPort;
        this.contentType = servletInfo.contentType.trim();
        this.parameterMap = new HashMap<>(servletInfo.parameterMap);
        this.protocol = servletInfo.protocol;
        this.clientPort = servletInfo.clientPort;
        this.isRequestParsed = servletInfo.isRequestParsed;
        this.isGrpc = servletInfo.isGrpc;
        this.route = servletInfo.route;
        this.requestURI = servletInfo.requestURI;
        this.pathParameterMap = servletInfo.pathParameterMap;
        this.queryParameters = servletInfo.queryParameters;
        this.requestHeaderParameters = servletInfo.requestHeaderParameters;
        this.requestBodyParameters = servletInfo.requestBodyParameters;
        this.isRequestParametersParsed = servletInfo.isRequestParametersParsed;
        this.customDataType = servletInfo.customDataType;
        this.pathParameters = servletInfo.pathParameters;
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
        this.requestURI = StringUtils.substringBefore(url, QUESTION_MARK);
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
    public StringBuilderLimit getBody() {
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
        this.body.sb = body;
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

    public boolean getIsGrpc() {
        return isGrpc;
    }

    public void setIsGrpc(boolean grpc) {
        isGrpc = grpc;
    }
    public String getRoute() {
        return route;
    }

    public void setRoute(String route){
        this.route = StringUtils.removeEnd(StringUtils.prependIfMissing(route, StringUtils.SEPARATOR), StringUtils.SEPARATOR);
    }

    public String getRequestURI() {
        return requestURI;
    }

    public void setRequestURI(String requestURI) {
        this.requestURI = requestURI;
    }

    public void setRoute(String segment, boolean isAlreadyServlet) {
        // remove servlet detected route if another framework detected;
        if (isAlreadyServlet) {
            this.route = StringUtils.EMPTY;
        }
        String formatedSegment = StringUtils.prependIfMissing(StringUtils.removeEnd(segment, StringUtils.SEPARATOR), StringUtils.SEPARATOR);
        if (!StringUtils.isEmpty(formatedSegment)) {
            this.route = Paths.get(this.route, formatedSegment).normalize().toString();
        }
    }

    public Set<String> getPathParameters() {
        return pathParameters;
    }

    public void setPathParameters(Set<String> pathParameters) {
        this.pathParameters = pathParameters;
    }

    public Map<String, Set<String>> getQueryParameters() {
        return queryParameters;
    }

    public void setQueryParameters(Map<String, Set<String>> queryParameters) {
        this.queryParameters = queryParameters;
    }

    public Map<String, Set<String>> getRequestHeaderParameters() {
        return requestHeaderParameters;
    }

    public void setRequestHeaderParameters(Map<String, Set<String>> requestHeaderParameters) {
        this.requestHeaderParameters = requestHeaderParameters;
    }

    public Map<String, Set<String>> getRequestBodyParameters() {
        return requestBodyParameters;
    }

    public void setRequestBodyParameters(Map<String, Set<String>> requestBodyParameters) {
        this.requestBodyParameters = requestBodyParameters;
    }

    public boolean isRequestParametersParsed() {
        return isRequestParametersParsed;
    }

    public void setRequestParametersParsed(boolean requestParametersParsed) {
        isRequestParametersParsed = requestParametersParsed;
    }

    public Map<String, String> getCustomDataType() {
        return customDataType;
    }

    public void clean () {
        this.body.clean();
        this.headers.clear();
        this.serverPort = -1;
        this.parameterMap.clear();
        this.protocol = HTTP;
        this.clientPort = StringUtils.EMPTY;
        this.isRequestParsed = false;
        this.isGrpc = false;
        this.route = StringUtils.EMPTY;
        this.requestURI = StringUtils.EMPTY;
        this.pathParameterMap.clear();
        this.queryParameters.clear();
        this.requestHeaderParameters.clear();
        this.requestBodyParameters.clear();
        this.isRequestParametersParsed = false;
        this.customDataType.clear();
    }

}


