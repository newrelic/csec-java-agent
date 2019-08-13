package com.k2cybersecurity.intcodeagent.logging;

import org.brutusin.instrumentation.Agent;

import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;

public class AgentUtils {
	
	public static void controlCommandProcessor(IntCodeControlCommand controlCommand) {
		switch (controlCommand.getControlCommand()) {
		case IntCodeControlCommand.CHANGE_LOG_LEVEL:
			break;

		case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
			LoggingInterceptor.shutdownLogic(Runtime.getRuntime(), Agent.classTransformer);
			break;
			
		default:
			break;
		}
	}
}
