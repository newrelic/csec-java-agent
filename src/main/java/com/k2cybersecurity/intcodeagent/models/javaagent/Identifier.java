/**
 * 
 */
package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

/**
 * @author lovesh
 *
 */
public class Identifier {

    private String id;
    private IdentifierEnvs kind;

    /**
     * IC properties
     */
    private String nodeName;
    private String nodeId;
    private String nodeIp;

    /**
     * Below properties will be used later.
     */
    private String collectorIp;

    private EnvInfo envInfo;

    public Identifier() {
    }

    public Identifier(String nodeName, String nodeId, String nodeIp) {
        this.nodeName = nodeName;
        this.nodeId = nodeId;
        this.nodeIp = nodeIp;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public IdentifierEnvs getKind() {
        return kind;
    }

    public void setKind(IdentifierEnvs kind) {
        this.kind = kind;
    }

    public String getNodeName() {
        return nodeName;
    }

    public void setNodeName(String nodeName) {
        this.nodeName = nodeName;
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

    public String getCollectorIp() {
        return collectorIp;
    }

    public void setCollectorIp(String collectorIp) {
        this.collectorIp = collectorIp;
    }

    public EnvInfo getEnvInfo() {
        return envInfo;
    }

    public void setEnvInfo(EnvInfo envInfo) {
        this.envInfo = envInfo;
    }

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}
}
