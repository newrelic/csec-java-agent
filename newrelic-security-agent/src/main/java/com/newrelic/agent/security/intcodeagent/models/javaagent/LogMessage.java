package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LogMessage {

    private String jsonName = "critical-messages";

    private String applicationUUID = AgentInfo.getInstance().getApplicationUUID();

    private Long timestamp;

    private String level;

    private String message;

    private String caller;
    private LogMessageException exception;

    private Map<String, String> linkingMetadata;

    private String threadName;
    private String appAccountId;
    private String appEntityGuid;

    public LogMessage(String level, String message, String caller, Throwable exception, Map<String, String> linkingMetadata) {
        this.timestamp = Instant.now().toEpochMilli();
        this.level = level;
        this.message = message;
        this.caller = caller;
        this.linkingMetadata = linkingMetadata;
        if (exception != null) {
            this.exception = new LogMessageException(exception, 0, 1);
        }
        this.threadName = Thread.currentThread().getName();
        this.appEntityGuid = AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY);
        if (AgentConfig.getInstance().getConfig().getCustomerInfo() != null) {
            this.appAccountId = AgentConfig.getInstance().getConfig().getCustomerInfo().getAccountId();
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


    public String getJsonName() {
        return jsonName;
    }

    public void setJsonName(String jsonName) {
        this.jsonName = jsonName;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }


    public String getThreadName() {
        return threadName;
    }

    public void setThreadName(String threadName) {
        this.threadName = threadName;
    }

    public String getAppAccountId() {
        return appAccountId;
    }

    public void setAppAccountId(String appAccountId) {
        this.appAccountId = appAccountId;
    }

    public String getAppEntityGuid() {
        return appEntityGuid;
    }

    public void setAppEntityGuid(String appEntityGuid) {
        this.appEntityGuid = appEntityGuid;
    }
    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
