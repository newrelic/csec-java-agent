
package com.newrelic.agent.security.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "interval",
        "batchSize"
})
public class Probing {

    @JsonProperty("interval")
    private Integer interval = 1;
    @JsonProperty("batchSize")
    private Integer batchSize = 10;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public Probing() {
    }

    /**
     * @param interval
     * @param batchSize
     */
    public Probing(Integer interval, Integer batchSize) {
        super();
        this.interval = interval;
        this.batchSize = batchSize;
    }

    @JsonProperty("interval")
    public Integer getInterval() {
        return interval;
    }

    @JsonProperty("interval")
    public void setInterval(Integer interval) {
        this.interval = interval;
    }

    @JsonProperty("batchSize")
    public Integer getBatchSize() {
        return batchSize;
    }

    @JsonProperty("batchSize")
    public void setBatchSize(Integer batchSize) {
        this.batchSize = batchSize;
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
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return StringUtils.EMPTY;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Probing probing = (Probing) o;
        return Objects.equals(interval, probing.interval) &&
                Objects.equals(batchSize, probing.batchSize);
    }

    @Override
    public int hashCode() {
        return Objects.hash(interval, batchSize);
    }
}
