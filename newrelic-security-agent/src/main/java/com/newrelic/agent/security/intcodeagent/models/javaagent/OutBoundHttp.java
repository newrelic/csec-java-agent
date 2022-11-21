package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class OutBoundHttp {
    @JsonIgnore
    private Integer hashCode;

    private String url;

    private String sourceIp;

    private String destinationIp;

    private Integer destinationPort;

    private Integer sourcePort;

    private OutBoundHttpDirection direction;

    private AtomicInteger count;

    private OutboundHttpSourceId sourceId;

    public OutBoundHttp(String url, String sourceIp, String destinationIp, OutBoundHttpDirection direction, OutboundHttpSourceId sourceId) {
        this.url = url;
        this.sourceIp = sourceIp;
        this.direction = direction;
        this.destinationIp = destinationIp;
        this.count = new AtomicInteger(1);
        this.sourceId = sourceId;
        this.hashCode = Objects.hash(url, direction, sourceIp, destinationIp, sourceId);
    }

    public OutBoundHttp(OutBoundHttp outBoundHttp) {
        this.url = outBoundHttp.url;
        this.sourceIp = outBoundHttp.sourceIp;
        this.destinationIp = outBoundHttp.destinationIp;
        this.destinationPort = outBoundHttp.destinationPort;
        this.sourcePort = outBoundHttp.sourcePort;
        this.direction = outBoundHttp.direction;
        this.count = new AtomicInteger(outBoundHttp.count.get());
        if (outBoundHttp.sourceId != null) {
            this.sourceId = new OutboundHttpSourceId(outBoundHttp.sourceId);
        }
        this.hashCode = Objects.hash(url, direction, sourceIp, destinationIp, sourceId);
    }

    public String getUrl() {
        return url;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    public OutBoundHttpDirection getDirection() {
        return direction;
    }

    public Integer getHashCode() {
        return hashCode;
    }

    public AtomicInteger getCount() {
        return count;
    }

    public void setCount(AtomicInteger count) {
        this.count = count;
    }

    public OutboundHttpSourceId getSourceId() {
        return sourceId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OutBoundHttp that = (OutBoundHttp) o;
        return Objects.equals(url, that.url) && Objects.equals(direction, that.direction) && Objects.equals(sourceIp, that.sourceIp) && Objects.equals(destinationIp, that.destinationIp) && Objects.equals(sourceId, that.sourceId);
    }

    @Override
    public int hashCode() {
        return this.hashCode;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
