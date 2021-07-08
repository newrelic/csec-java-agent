package com.k2cybersecurity.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.k2cybersecurity.intcodeagent.models.config.PolicyApplicationInfo;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashSet;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class CollectorConfig {

    private String nodeId;

    private String nodeIp;

    private String nodeName;

    private K2ServiceInfo k2ServiceInfo;

    private Set<String> nodeGroupTags = new HashSet<>();

    private CustomerInfo customerInfo;

    private PolicyApplicationInfo applicationInfo;

    public CollectorConfig() {
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

    public PolicyApplicationInfo getApplicationInfo() {
        return applicationInfo;
    }

    public void setApplicationInfo(PolicyApplicationInfo applicationInfo) {
        this.applicationInfo = applicationInfo;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}
