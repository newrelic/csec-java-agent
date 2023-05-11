package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.util.List;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IntCodeControlCommand {

    public static final int SHUTDOWN_LANGUAGE_AGENT = 1;
    public static final int UNSUPPORTED_AGENT = 5;
    public static final int EVENT_RESPONSE = 6;
    public static final int OLD_AGENT = 7;
    public static final int STARTUP_WELCOME_MSG = 10;

    public static final int FUZZ_REQUEST = 11;
    public static final int RECONNECT_AT_WILL = 12;
    public static final int ENTER_IAST_COOLDOWN = 13;
    public static final int IAST_RECORD_DELETE_CONFIRMATION = 14;
    public static final int SEND_POLICY = 100;
    public static final int SEND_POLICY_PARAMETERS = 101;
    public static final int POLICY_UPDATE_FAILED_DUE_TO_VALIDATION_ERROR = 102;

    private String id;

    private String jsonName;
    private int controlCommand;
    private Object data;
    private List<String> arguments;

    public IntCodeControlCommand() {
    }

    /**
     * @return the jsonName
     */
    public String getJsonName() {
        return jsonName;
    }

    /**
     * @param jsonName the jsonName to set
     */
    public void setJsonName(String jsonName) {
        this.jsonName = jsonName;
    }

    /**
     * @return the controlCommand
     */
    public int getControlCommand() {
        return controlCommand;
    }

    /**
     * @param controlCommand the controlCommand to set
     */
    public void setControlCommand(int controlCommand) {
        this.controlCommand = controlCommand;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    /**
     * @return the arguments
     */
    public List<String> getArguments() {
        return arguments;
    }

    /**
     * @param arguments the arguments to set
     */
    public void setArguments(List<String> arguments) {
        this.arguments = arguments;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
