package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;

public class HttpResponseEvent extends AgentBasicInfo {
    private String traceId;

    private HttpResponse httpResponse;

    private HttpRequest httpRequest;

    private boolean isIastRequest;

    public HttpResponseEvent(HttpResponse httpResponse, boolean isIastRequest) {
        super();
        this.httpResponse = new HttpResponse(httpResponse);
        this.isIastRequest = isIastRequest;
        this.traceId = getLinkingMetadata().get(IAgentConstants.NR_APM_TRACE_ID);
    }

    public HttpResponseEvent(HttpResponseEvent httpResponseEvent) {
        this.traceId = httpResponseEvent.getTraceId();
        this.httpResponse = new HttpResponse(httpResponseEvent.getHttpResponse());
        this.httpRequest = new HttpRequest(httpResponseEvent.getHttpRequest());
        this.isIastRequest = httpResponseEvent.getIsIASTRequest();
    }

    public String getTraceId() {
        return traceId;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public HttpResponse getHttpResponse() {
        return httpResponse;
    }

    public void setHttpResponse(HttpResponse httpResponse) {
        this.httpResponse = httpResponse;
    }

    public HttpRequest getHttpRequest() {
        return httpRequest;
    }

    public void setHttpRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    public boolean getIsIASTRequest() {
        return isIastRequest;
    }

    public void setIsIASTRequest(boolean iastRequest) {
        isIastRequest = iastRequest;
    }

    public boolean isEmpty() {
        return traceId == null || httpResponse == null || httpResponse.getStatusCode() <= 0;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
