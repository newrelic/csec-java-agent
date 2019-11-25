package com.k2cybersecurity.intcodeagent.websocket;

import java.net.URI;
import java.net.URISyntaxException;

import com.k2cybersecurity.instrumentation.Agent;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.AgentUtils;
import com.k2cybersecurity.intcodeagent.logging.LoggingInterceptor;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;

public class WSClient extends WebSocketClient {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static WSClient instance;

	private WSClient() throws URISyntaxException, InterruptedException {
		super(new URI(String.format("ws://%s:%s", LoggingInterceptor.hostip, 54321)));
		logger.log(LogLevel.INFO, "Creating WSock connection to : " + LoggingInterceptor.hostip,
				WSClient.class.getName());
		if (!connectBlocking()) {
			logger.log(LogLevel.SEVERE, "WSock connection to " + LoggingInterceptor.hostip + " failed",
					WSClient.class.getName());
		}
	}

	@Override
	public void onOpen(ServerHandshake handshakedata) {
		logger.log(LogLevel.INFO, "Opened WSock to " + this.getRemoteSocketAddress(), WSClient.class.getName());
//		logger.log(LogLevel.INFO, "Current WSock ready status : {0},{1},{2}",
//				new Object[] { this.isOpen(), this.isClosing(), this.isClosed() });
		super.send(LoggingInterceptor.APPLICATION_INFO_BEAN.toString());
		Agent.allClassLoadersCount.set(0);
		Agent.jarPathSet.clear();
		logger.log(LogLevel.INFO, "Resetting allClassLoadersCount to " + Agent.allClassLoadersCount.get(),
				WSClient.class.getName());
		logger.log(LogLevel.INFO, "Application info posted : " + LoggingInterceptor.APPLICATION_INFO_BEAN,
				WSClient.class.getName());
	}

	@Override
	public void onMessage(String message) {
		// TODO : Receive communication from IC side.
		// logger.log(Level.FINE, "Message from IC : {0}", message);
		try {
			IntCodeControlCommand controlCommand = new ObjectMapper().readValue(message, IntCodeControlCommand.class);
			AgentUtils.controlCommandProcessor(controlCommand);
		} catch (Exception e) {
			logger.log(LogLevel.SEVERE, "Unable to process incoming message : " + message + " : due to error : ", e,
					WSClient.class.getName());
		}
	}

	@Override
	public void onClose(int code, String reason, boolean remote) {
		logger.log(LogLevel.WARNING, "Connection closed by " + (remote ? "remote peer." : "local.") + " Code: " + code
				+ " Reason: " + reason, WSClient.class.getName());
	}

	@Override
	public void onError(Exception ex) {
		logger.log(LogLevel.SEVERE, "Error in WSock connection : " + ex.getMessage() + " : " + ex.getCause(),
				WSClient.class.getName());
	}

	@Override
	public void send(String text) {
		if (this.isOpen()) {
			logger.log(LogLevel.DEBUG, "sending event: " + text, WSClient.class.getName());
			super.send(text);
		} else {
			logger.log(LogLevel.DEBUG, "Unable to send event : " + text, WSClient.class.getName());
		}
	}

	/**
	 * @return the instance
	 * @throws URISyntaxException
	 * @throws InterruptedException
	 */
	public static WSClient getInstance() throws URISyntaxException, InterruptedException {
		if (instance == null) {
			instance = new WSClient();
		}
		return instance;
	}

	/**
	 * @return the instance
	 * @throws URISyntaxException
	 * @throws InterruptedException
	 */
	public static WSClient reconnectWSClient() throws URISyntaxException, InterruptedException {
		logger.log(LogLevel.WARNING, "Reconnecting with IC. Open status: " + instance.isOpen(),
				WSClient.class.getName());
		boolean reconnectStatus = false;
		if (instance != null) {
			instance.closeBlocking();
			try {
				reconnectStatus = instance.reconnectBlocking();
			} catch (Exception e) {
				reconnectStatus = false;
			}
		}
		if (!reconnectStatus) {
			if (instance != null) {
				instance.closeBlocking();
			}
			instance = new WSClient();
		}
		return instance;
	}
}
