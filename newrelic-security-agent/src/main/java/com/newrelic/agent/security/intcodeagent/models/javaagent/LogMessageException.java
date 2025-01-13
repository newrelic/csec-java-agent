package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LogMessageException {

    private String type;

    private String message;

    private LogMessageException cause;

    private String[] stackTrace;

    public LogMessageException(Throwable exception, int nestingLevel, int maxNestingLevel) {
        this.type = exception.getClass().getName();
        this.message = exception.getMessage();
        StackTraceElement[] trace = exception.getStackTrace();
        this.stackTrace = new String[trace.length];
        for (int index = 0; index < trace.length; index++) {
            this.stackTrace[index] = AgentUtils.stackTraceElementToString(trace[index]);
        }
        if (exception.getCause() != null && nestingLevel < maxNestingLevel) {
            this.cause = new LogMessageException(exception.getCause(), nestingLevel++, maxNestingLevel);
        }
    }

    public LogMessageException(Throwable exception, int nestingLevel, int maxNestingLevel, int max) {
        this.type = exception.getClass().getName();
        this.message = exception.getMessage();
        StackTraceElement[] trace = exception.getStackTrace();
        this.stackTrace = new String[Math.min(trace.length, max)];
        for (int index = 0; index < trace.length && index < max; index++) {
            this.stackTrace[index] = AgentUtils.stackTraceElementToString(trace[index]);
        }
        if (exception.getCause() != null && nestingLevel < maxNestingLevel) {
            this.cause = new LogMessageException(exception.getCause(), nestingLevel++, maxNestingLevel, max);
        }
    }

    public String getMessage() {
        return message;
    }

    public LogMessageException getCause() {
        return cause;
    }

    public String[] getStackTrace() {
        return stackTrace;
    }

    public String getType() {
        return type;
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, stackTrace[0]);
    }
}
