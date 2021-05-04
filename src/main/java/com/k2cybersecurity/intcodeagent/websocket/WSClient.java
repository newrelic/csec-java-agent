package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.controlcommand.ControlCommandProcessor;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.net.URISyntaxException;

public class WSClient extends WebSocketClient {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static WSClient instance;

	private WSClient() throws URISyntaxException, InterruptedException {
		super(new URI(String.format("ws://%s:%s", CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress(), CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointPort())));
		this.setTcpNoDelay(true);
		logger.log(LogLevel.INFO, "Creating WSock connection to : " + CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress(),
				WSClient.class.getName());
		if (!connectBlocking()) {
			logger.log(LogLevel.SEVERE, "WSock connection to " + CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress() + " failed",
					WSClient.class.getName());
			throw new InterruptedException("Unable to connect K2 Agent. Initial connect failed.");
		}
	}

	@Override
	public void onOpen(ServerHandshake handshakedata) {
		logger.log(LogLevel.INFO, "Opened WSock to " + this.getRemoteSocketAddress(), WSClient.class.getName());
//		logger.log(LogLevel.INFO, "Current WSock ready status : {0},{1},{2}",
//				new Object[] { this.isOpen(), this.isClosing(), this.isClosed() });
		super.send(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
//		Agent.allClassLoadersCount.set(0);
//		Agent.jarPathSet.clear();
//		logger.log(LogLevel.INFO, "Resetting allClassLoadersCount to " + Agent.allClassLoadersCount.get(),
//				WSClient.class.getName());
		logger.log(LogLevel.INFO, "Application info posted : " + K2Instrumentator.APPLICATION_INFO_BEAN,
				WSClient.class.getName());
		AgentUtils.getInstance().resetCVEServiceFailCount();
	}

	@Override
	public void onMessage(String message) {
		// Receive communication from IC side.
		try {
			ControlCommandProcessor.processControlCommand(message, System.currentTimeMillis());
		} catch (Throwable e) {
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
		logger.log(LogLevel.SEVERE, "Error in WSock connection : " + ex.getMessage() + " : " + ex.getCause(), ex,
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
			} catch (Throwable e) {
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
