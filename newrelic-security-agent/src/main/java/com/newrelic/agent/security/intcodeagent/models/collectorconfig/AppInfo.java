package com.newrelic.agent.security.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.*;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.*;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class AppInfo {

    private String name;

    private String version;

    private Set<String> tags = new HashSet<>();

    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    public AppInfo() {
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Set<String> getTags() {
        return tags;
    }

    public void setTags(Set<String> tags) {
        this.tags = tags;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppInfo appInfo = (AppInfo) o;
        return Objects.equals(name, appInfo.name) &&
                Objects.equals(version, appInfo.version) &&
                Objects.equals(tags, appInfo.tags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, version, tags);
    }
}
