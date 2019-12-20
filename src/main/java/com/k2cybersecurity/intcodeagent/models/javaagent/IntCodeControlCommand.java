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

	private String jsonName;
	private int controlCommand;
	private List<String> arguements;

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
	 * @return the arguements
	 */
	public List<String> getArguements() {
		return arguements;
	}

	/**
	 * @param arguements the arguements to set
	 */
	public void setArguements(List<String> arguements) {
		this.arguements = arguements;
	}
}
