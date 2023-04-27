package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class RXSSOperation extends AbstractOperation {

    private HttpRequest request;

    private HttpResponse response;

    public RXSSOperation(HttpRequest  request, HttpResponse response, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.REFLECTED_XSS);
        this.request = request;
        this.response = response;
    }

    @Override
    public boolean isEmpty() {
        return (request == null || request.isEmpty() || response == null || response.isEmpty());
    }

    public HttpRequest getRequest() {
        return request;
    }

    public void setRequest(HttpRequest request) {
        this.request = request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public void setResponse(HttpResponse response) {
        this.response = response;
    }
}
