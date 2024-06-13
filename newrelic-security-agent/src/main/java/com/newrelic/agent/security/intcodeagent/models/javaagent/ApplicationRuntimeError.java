package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class ApplicationRuntimeError extends AgentBasicInfo{

    private Long timestamp;

    private HttpRequest httpRequest;

    private LogMessageException exception;

    private final AtomicInteger counter = new AtomicInteger(1);

    private int responseCode = 0;

    private String category;

    private String applicationUUID;

    @JsonIgnore
    private String route;

    public ApplicationRuntimeError(HttpRequest httpRequest, LogMessageException exception, String category, String applicationUUID) {
        super();
        this.timestamp = Instant.now().toEpochMilli();
        this.httpRequest = httpRequest;
        this.exception = exception;
        this.category = category;
        this.applicationUUID = applicationUUID;
    }

    public ApplicationRuntimeError(HttpRequest httpRequest, LogMessageException exception, int responseCode, String route, String category, String applicationUUID) {
        super();
        this.timestamp = Instant.now().toEpochMilli();
        this.httpRequest = httpRequest;
        this.exception = exception;
        this.responseCode = responseCode;
        this.route = route;
        this.category = category;
        this.applicationUUID = applicationUUID;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public HttpRequest getHttpRequest() {
        return httpRequest;
    }

    public void setHttpRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    public LogMessageException getException() {
        return exception;
    }

    public void setException(LogMessageException exception) {
        this.exception = exception;
    }

    public AtomicInteger getCounter() {
        return counter;
    }

    public int incrementCounter() {
        return counter.incrementAndGet();
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getRoute() {
        return route;
    }

    public void setRoute(String route) {
        this.route = route;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    @Override
    public int hashCode() {
        return (responseCode == 0) ? exception.hashCode(): Objects.hash(route, responseCode);
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
