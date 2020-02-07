package com.k2cybersecurity.instrumentator.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class AgentUtils {

	public Set<Pair<String, ClassLoader>> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<Pair<String, ClassLoader>> transformedClasses;

	private static AgentUtils instance;


	private AgentUtils(){
		transformedClasses = new HashSet<>();
	}

	public static AgentUtils getInstance() {
		if(instance == null) {
			instance = new AgentUtils();
		}
		return instance;
	}

	public void clearTransformedClassSet(){
		transformedClasses.clear();
	}

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static void controlCommandProcessor(IntCodeControlCommand controlCommand) {
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
				logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e, AgentUtils.class.getSimpleName());
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
					AgentUtils.class.getSimpleName());
			break;
		case IntCodeControlCommand.UNSUPPORTED_AGENT:
			logger.log(LogLevel.SEVERE, controlCommand.getArguments().get(0), AgentUtils.class.getSimpleName());
			System.err.println(controlCommand.getArguments().get(0));
			HealthCheckScheduleThread.getInstance().shutDownThreadPoolExecutor();
			InstrumentationUtils.shutdownLogic(false);
			break;
		case IntCodeControlCommand.EVENT_RESPONSE:
			long receivedTime = System.currentTimeMillis();
			EventResponse eventResponse = null;
			try {
				eventResponse = new ObjectMapper().readValue(controlCommand.getArguments().get(0), EventResponse.class);
			} catch (JsonProcessingException e) {
				e.printStackTrace();
			}
			long generationTime = EventSendPool.getInstance().getEventMap().get(eventResponse.getId());
			EventSendPool.getInstance().getEventMap().remove(eventResponse.getId());
			if(eventResponse != null) {
				logger.log(LogLevel.INFO, "Event response time taken : " + (receivedTime - generationTime), AgentUtils.class.getSimpleName());
			}
			break;
		default:
			break;
		}
	}
}
