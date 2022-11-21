package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.time.Instant;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LogMessage {

    private Long timestamp;

    private String level;

    private String message;

    private String caller;
    private LogMessageException exception;

    private Map<String, String> linkingMetadata;

    public LogMessage(String level, String message, String caller, Throwable exception, Map<String, String> linkingMetadata) {
        this.timestamp = Instant.now().toEpochMilli();
        this.level = level;
        this.message = message;
        this.caller = caller;
        this.linkingMetadata = linkingMetadata;
        if (exception != null) {
            this.exception = new LogMessageException(exception, 0, 1);
        }
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public String getLevel() {
        return level;
    }

    public String getMessage() {
        return message;
    }

    public String getCaller() {
        return caller;
    }

    public LogMessageException getException() {
        return exception;
    }

    public Map<String, String> getLinkingMetadata() {
        return linkingMetadata;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
