package com.k2cybersecurity.intcodeagent.controlcommand;

import com.google.gson.Gson;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.TimeUnit;

public class ControlCommandProcessor implements Runnable {

	public static final Gson GSON = new Gson();
	public static final String EVENT_RESPONSE_ENTRY_NOT_FOUND_FOR_THIS_S = "Event response entry not found for this : %s";
	public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
	public static final String DOUBLE_COLON_SEPERATOR = " :: ";
	public static final String VULNERABLE_API_ENTRY_CREATED = "vulnerableAPI entry created : ";
	public static final String FAILED_TO_CREATE_VULNERABLE_API_ENTRY = "Failed to create vulnerableAPI entry  : ";
	public static final String EVENT_RESPONSE = "Event response : ";
	private String controlCommandMessage;

	private long receiveTimestamp;

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public ControlCommandProcessor(String controlCommandMessage, long receiveTimestamp) {
		this.controlCommandMessage = controlCommandMessage;
		this.receiveTimestamp = receiveTimestamp;
	}

	@Override public void run() {
		if (StringUtils.isBlank(controlCommandMessage)) {
			return;
		}
		IntCodeControlCommand controlCommand = null;
		try {
			controlCommand = GSON.fromJson(controlCommandMessage, IntCodeControlCommand.class);
		} catch (Exception e) {
			logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e,
					ControlCommandProcessor.class.getSimpleName());
			return;
		}

		switch (controlCommand.getControlCommand()) {
		case IntCodeControlCommand.CHANGE_LOG_LEVEL:
			if (controlCommand.getArguments().size() < 3)
				break;
			try {
				LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
				Integer duration = Integer.parseInt(controlCommand.getArguments().get(1));
				TimeUnit timeUnit = TimeUnit.valueOf(controlCommand.getArguments().get(2));
				LogWriter.updateLogLevel(logLevel, timeUnit, duration);
			} catch (Exception e) {
				logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e,
						ControlCommandProcessor.class.getSimpleName());
			}
			break;

		case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
			InstrumentationUtils.shutdownLogic(true);
			break;
		case IntCodeControlCommand.SET_DEFAULT_LOG_LEVEL:
			LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
			LogWriter.setLogLevel(logLevel);
			break;
		case IntCodeControlCommand.ENABLE_HTTP_REQUEST_PRINTING:
			K2Instrumentator.enableHTTPRequestPrinting = !K2Instrumentator.enableHTTPRequestPrinting;
			break;
		case IntCodeControlCommand.UPLOAD_LOGS:
			logger.log(LogLevel.INFO, "Is log file sent to IC: " + FtpClient.sendBootstrapLogFile(),
					ControlCommandProcessor.class.getSimpleName());
			break;
		case IntCodeControlCommand.UNSUPPORTED_AGENT:
			logger.log(LogLevel.SEVERE, controlCommand.getArguments().get(0),
					ControlCommandProcessor.class.getSimpleName());
			System.err.println(controlCommand.getArguments().get(0));
			InstrumentationUtils.shutdownLogic(true);
			break;
		case IntCodeControlCommand.EVENT_RESPONSE:
			EventResponse eventResponse = AgentUtils.getInstance().getEventResponseSet()
					.get(controlCommand.getArguments().get(0));
			if (eventResponse == null) {
				logger.log(LogLevel.WARNING,
						String.format(EVENT_RESPONSE_ENTRY_NOT_FOUND_FOR_THIS_S, controlCommand.getArguments().get(0)),
						ControlCommandProcessor.class.getSimpleName());
				return;
			}
			eventResponse.setId(controlCommand.getArguments().get(0));
			eventResponse.setEventId(controlCommand.getArguments().get(1));
			eventResponse.setAttack(Boolean.parseBoolean(controlCommand.getArguments().get(2)));
			eventResponse.setResultMessage(controlCommand.getArguments().get(3));

			eventResponse.setGenerationTime(EventSendPool.getInstance().getEventMap().get(eventResponse.getId()));
			eventResponse.setReceivedTime(receiveTimestamp);

			EventSendPool.getInstance().getEventMap().remove(eventResponse.getId());
			logger.log(LogLevel.INFO, EVENT_RESPONSE + eventResponse.toString(), ControlCommandProcessor.class.getName());
			if (eventResponse.isAttack() && ProtectionConfig.getInstance().getAutoAddDetectedVulnerabilitiesToProtectionList()) {
				try {
					VulnerableAPI vulnerableAPI = new VulnerableAPI(controlCommand.getArguments().get(4),
							controlCommand.getArguments().get(5),
							controlCommand.getArguments().get(6),
							Integer.parseInt(controlCommand.getArguments().get(7)));
					AgentUtils.getInstance().getVulnerableAPIMap().put(vulnerableAPI.getId(), vulnerableAPI);
					logger.log(LogLevel.INFO, VULNERABLE_API_ENTRY_CREATED + vulnerableAPI, ControlCommandProcessor.class.getName());
				} catch (Exception e){
					logger.log(LogLevel.SEVERE,
							FAILED_TO_CREATE_VULNERABLE_API_ENTRY + controlCommand,e,
							ControlCommandProcessor.class.getSimpleName());
				}
			}
			eventResponse.getResponseSemaphore().release();
			AgentUtils.getInstance().getEventResponseSet().remove(eventResponse.getId());

			logger.log(LogLevel.INFO,
					EVENT_RESPONSE_TIME_TAKEN + eventResponse.getEventId() + DOUBLE_COLON_SEPERATOR + (
							eventResponse.getReceivedTime() - eventResponse.getGenerationTime()),
					EventDispatcher.class.getSimpleName());
			break;
		case IntCodeControlCommand.PROTECTION_CONFIG:
			ProtectionConfig protectionConfig = GSON.fromJson(controlCommand.getArguments().get(0), ProtectionConfig.class);
			ProtectionConfig.setInstance(protectionConfig);
			if (!ProtectionConfig.getInstance().getGenerateEventResponse()) {
				ProtectionConfig.getInstance().setProtectKnownVulnerableAPIs(false);
			}
			if(!ProtectionConfig.getInstance().getProtectKnownVulnerableAPIs()){
				ProtectionConfig.getInstance().setAutoAddDetectedVulnerabilitiesToProtectionList(false);
			}
			logger.log(LogLevel.INFO,
					"Setting to  : " + ProtectionConfig.getInstance().getGenerateEventResponse(),
					ControlCommandProcessor.class.getSimpleName());
			logger.log(LogLevel.INFO,
					"Setting protection for known vulnerable APIs : " + ProtectionConfig.getInstance().getProtectKnownVulnerableAPIs(),
					ControlCommandProcessor.class.getSimpleName());
			logger.log(LogLevel.INFO,
					"Setting auto add detected vulnerable APIs to protection list : " + ProtectionConfig.getInstance().getAutoAddDetectedVulnerabilitiesToProtectionList(),
					ControlCommandProcessor.class.getSimpleName());
			break;
		default:
			break;
		}
	}

	public static void processControlCommand(String controlCommandMessage, long receiveTimestamp) {
		ControlCommandProcessorThreadPool.getInstance().executor
				.submit(new ControlCommandProcessor(controlCommandMessage, receiveTimestamp));
	}
}
