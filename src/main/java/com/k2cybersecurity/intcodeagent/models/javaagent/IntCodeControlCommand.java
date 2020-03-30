package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.util.List;

@JsonInclude(Include.NON_NULL)
public class IntCodeControlCommand {

    public static final int CHANGE_LOG_LEVEL = 0;
    public static final int SHUTDOWN_LANGUAGE_AGENT = 1;
    public static final int SET_DEFAULT_LOG_LEVEL = 2;
    public static final int ENABLE_HTTP_REQUEST_PRINTING = 3;
    public static final int UPLOAD_LOGS = 4;
    public static final int UNSUPPORTED_AGENT = 5;
    public static final int EVENT_RESPONSE = 6;
    public static final int PROTECTION_CONFIG = 7;
    public static final int START_VULNERABILITY_SCAN = 8;
    public static final int SET_IPBLOCKING_TIMEOUT = 9;
    public static final int CREATE_IPBLOCKING_ENTR¥ = 10;

    private String jsonName;
    private int controlCommand;
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
}
