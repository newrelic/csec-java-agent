package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

import java.io.Serializable;

public class ShutDownEvent extends AgentBasicInfo implements Serializable {

    private static final long serialVersionUID = -2320594688008671870L;

    private String status;

    private JSONArray resonForTermination;

    private Integer exitCode;

    public ShutDownEvent() {
        super();
    }

    /**
     * @return the status
     */
    public String getStatus() {
        return status;
    }

    /**
     * @param status the status to set
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * @return the resonForTermination
     */
    public JSONArray getResonForTermination() {
        return resonForTermination;
    }

    /**
     * @param resonForTermination the resonForTermination to set
     */
    public void setResonForTermination(JSONArray resonForTermination) {
        this.resonForTermination = resonForTermination;
    }

    /**
     * @return the exitCode
     */
    public Integer getExitCode() {
        return exitCode;
    }

    /**
     * @param exitCode the exitCode to set
     */
    public void setExitCode(Integer exitCode) {
        this.exitCode = exitCode;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}
