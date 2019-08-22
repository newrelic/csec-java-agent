package com.k2cybersecurity.intcodeagent.websocket;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.brutusin.instrumentation.Agent;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonElement;
import com.k2cybersecurity.intcodeagent.logging.AgentUtils;
import com.k2cybersecurity.intcodeagent.logging.LoggingInterceptor;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;

public class WSClient extends WebSocketClient {

	private static Logger logger;

	private static WSClient instance;

	private WSClient() throws URISyntaxException, InterruptedException {
		super(new URI(String.format("ws://%s:%s", LoggingInterceptor.hostip, 54321)));
		logger.log(Level.INFO, "Creating WSock connection to : {0}", LoggingInterceptor.hostip);
		if (!connectBlocking()) {
			logger.log(Level.SEVERE, "WSock connection to {0} failed", LoggingInterceptor.hostip);
		}
	}

	@Override
	public void onOpen(ServerHandshake handshakedata) {
		logger.log(Level.INFO, "Opened WSock to {0}", this.getRemoteSocketAddress());
//		logger.log(Level.INFO, "Current WSock ready status : {0},{1},{2}",
//				new Object[] { this.isOpen(), this.isClosing(), this.isClosed() });
		super.send(LoggingInterceptor.APPLICATION_INFO_BEAN.toString());
		Agent.allClassLoadersCount.set(0);
		logger.log(Level.INFO, "Application info posted : {0}", LoggingInterceptor.APPLICATION_INFO_BEAN);
	}

	@Override
	public void onMessage(String message) {
		// TODO : Receive communication from IC side.
		//		logger.log(Level.FINE, "Message from IC : {0}", message);
		try {
			IntCodeControlCommand controlCommand = new ObjectMapper().readValue(message, IntCodeControlCommand.class);
			AgentUtils.controlCommandProcessor(controlCommand);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Unable to process incoming message : {0} : due to error : {1}", new Object[] {message, e});
		}
	}

	@Override
	public void onClose(int code, String reason, boolean remote) {
		logger.log(Level.WARNING, "Connection closed by " + (remote ? "remote peer." : "local.") + " Code: " + code
				+ " Reason: " + reason);
	}

	@Override
	public void onError(Exception ex) {
		logger.log(Level.SEVERE, "Error in WSock connection : " + ex.getMessage() + " : " + ex.getCause());
	}

	@Override
	public void send(String text) {
		if (this.isOpen()) {
			super.send(text);
		} else {
//			try {
//				if (this.reconnectBlocking()) {
//					super.send(text);
//				} else {
//					logger.log(Level.SEVERE, "Failed in WSock reconnection.");
//					reconnectWSClient();
//				}
//			} catch (URISyntaxException | InterruptedException e) {
//				logger.log(Level.SEVERE, "Error in WSock reconnection : " + e.getMessage() + " : " + e.getCause());
//			}
			logger.log(Level.WARNING, "Unable to send event : {0}", text);
		}
	}

	public static void setLogger() {
		WSClient.logger = Logger.getLogger(WSClient.class.getName());
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
			if (instance !=null) {
				instance.closeBlocking();
			}
			instance = new WSClient();
		}
		return instance;
	}
}
