package com.k2cybersecurity.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.*;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class NodeLevelConfig {
    private String nodeId;

    private String nodeIp;

    private String nodeName;

    private K2ServiceInfo k2ServiceInfo;

    private CustomerInfo customerInfo;

    private Set<String> nodeGroupTags = new HashSet<>();

    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    public NodeLevelConfig() {
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    public String getNodeIp() {
        return nodeIp;
    }

    public void setNodeIp(String nodeIp) {
        this.nodeIp = nodeIp;
    }

    public String getNodeName() {
        return nodeName;
    }

    public void setNodeName(String nodeName) {
        this.nodeName = nodeName;
    }

    public K2ServiceInfo getK2ServiceInfo() {
        return k2ServiceInfo;
    }

    public void setK2ServiceInfo(K2ServiceInfo k2ServiceInfo) {
        this.k2ServiceInfo = k2ServiceInfo;
    }

    public Set<String> getNodeGroupTags() {
        return nodeGroupTags;
    }

    public void setNodeGroupTags(Set<String> nodeGroupTags) {
        this.nodeGroupTags = nodeGroupTags;
    }

    public CustomerInfo getCustomerInfo() {
        return customerInfo;
    }

    public void setCustomerInfo(CustomerInfo customerInfo) {
        this.customerInfo = customerInfo;
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NodeLevelConfig that = (NodeLevelConfig) o;
        return Objects.equals(nodeId, that.nodeId) &&
                Objects.equals(nodeIp, that.nodeIp) &&
                Objects.equals(nodeName, that.nodeName) &&
                Objects.equals(k2ServiceInfo, that.k2ServiceInfo) &&
                Objects.equals(customerInfo, that.customerInfo) &&
                Objects.equals(nodeGroupTags, that.nodeGroupTags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(nodeId, nodeIp, nodeName, k2ServiceInfo, nodeGroupTags, customerInfo);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
