package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.HttpRequest;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

public class ApplicationRuntimeError extends AgentBasicInfo{

    private Long timestamp;

    private HttpRequest httpRequest;

    private LogMessageException exception;

    private final AtomicInteger counter = new AtomicInteger(1);

    public ApplicationRuntimeError(HttpRequest httpRequest, LogMessageException exception) {
        super();
        this.timestamp = Instant.now().toEpochMilli();
        this.httpRequest = httpRequest;
        this.exception = exception;
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

    @Override
    public int hashCode() {
        return exception.hashCode();
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
