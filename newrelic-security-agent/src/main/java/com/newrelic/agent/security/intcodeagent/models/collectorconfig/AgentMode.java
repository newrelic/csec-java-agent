package com.newrelic.agent.security.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.policy.IASTScan;
import com.newrelic.api.agent.security.schema.policy.RASPScan;
import com.newrelic.api.agent.security.schema.policy.ScanSchedule;
import com.newrelic.api.agent.security.schema.policy.SkipScan;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class AgentMode {

    private String mode;

    private IASTScan iastScan;

    private RASPScan raspScan;

    private SkipScan skipScan;

    private ScanSchedule scanSchedule;

    public AgentMode() {}

    public AgentMode(String mode) {
        this.mode = mode;
        iastScan = new IASTScan();
        raspScan = new RASPScan();
        skipScan = new SkipScan();
        scanSchedule = new ScanSchedule();
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public IASTScan getIastScan() {
        return iastScan;
    }

    public void setIastScan(IASTScan iastScan) {
        this.iastScan = iastScan;
    }

    public RASPScan getRaspScan() {
        return raspScan;
    }

    public void setRaspScan(RASPScan raspScan) {
        this.raspScan = raspScan;
    }

    public SkipScan getSkipScan() {
        return skipScan;
    }

    public void setSkipScan(SkipScan skipScan) {
        this.skipScan = skipScan;
    }

    public ScanSchedule getScanSchedule() {
        return scanSchedule;
    }

    public void setScanSchedule(ScanSchedule scanSchedule) {
        this.scanSchedule = scanSchedule;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
