package com.k2cybersecurity.intcodeagent.logging;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HOST_IP_PROPERTIES_FILE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.IPSCHEDULEDTHREAD_;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.URISyntaxException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

public class IPScheduledThread {

	private static IPScheduledThread instance;

	private static Logger logger;

	private static ScheduledExecutorService ipScheduledService;

	private IPScheduledThread() {
		Runnable runnable = new Runnable() {
			public void run() {
				try (BufferedReader reader = new BufferedReader(new FileReader(HOST_IP_PROPERTIES_FILE))) {
					String hostip = reader.readLine();

					try {
						// since tcp connection keep alive check is more than 2 hours
						// we send our custom object to check if connectino is still alive or not
						// this will be ignored by ic agent on the other side.

//						channel.write(ByteBuffer.wrap(new JAHealthCheck(LoggingInterceptor.JA_HEALTH_CHECK).toString().getBytes()));
						if (WSClient.getInstance().isOpen()) {
							WSClient.getInstance()
									.send(new JAHealthCheck(LoggingInterceptor.JA_HEALTH_CHECK).toString());
							LoggingInterceptor.JA_HEALTH_CHECK.setEventDropCount(0);
							LoggingInterceptor.JA_HEALTH_CHECK.setEventProcessed(0);
							LoggingInterceptor.JA_HEALTH_CHECK.setEventSentCount(0);
						} else {
							try {
								WSClient.reconnectWSClient();
								if (WSClient.getInstance().isOpen()) {
									WSClient.getInstance()
											.send(new JAHealthCheck(LoggingInterceptor.JA_HEALTH_CHECK).toString());
									LoggingInterceptor.JA_HEALTH_CHECK.setEventDropCount(0);
								} else {
									logger.log(Level.SEVERE, "Failed in WSock reconnection.");
								}
							} catch (URISyntaxException | InterruptedException e) {
								logger.log(Level.SEVERE,
										"Error in WSock reconnection : " + e.getMessage() + " : " + e.getCause());
							}
						}

					} catch (NullPointerException ex) {
						logger.log(Level.WARNING, "No reference to Socket's OutputStream");
					} catch (Exception e) {
						logger.log(Level.WARNING, "Error while trying to verify connection: {0}", e);
					}
					if (hostip == null || hostip.equals("")) {
						logger.log(Level.FINE, "Host ip not found");
					} else if (!LoggingInterceptor.hostip.equals(hostip)) {
						LoggingInterceptor.hostip = hostip.trim();
						WSClient.reconnectWSClient();
						logger.log(Level.FINE, "K2-JavaAgent re-installed successfully coz of IP change.");
					} else if (!WSClient.getInstance().isOpen()) {
						WSClient.reconnectWSClient();
						logger.log(Level.FINE, "K2-JavaAgent re-installed successfully.");
					}
				} catch (Exception e) {
					logger.log(Level.WARNING, "Error in IPScheduledThread : {0}", e);
				}
			}
		};
		ipScheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						IPSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
			}
		});
		ipScheduledService.scheduleAtFixedRate(runnable, 5, 5, TimeUnit.MINUTES);
	}

	public static IPScheduledThread getInstance() {
		try {
			if (instance == null)
				instance = new IPScheduledThread();
			return instance;
		} catch (Exception e) {
			logger.log(Level.WARNING, "Error while starting: {0}", e);
		}
		throw null;
	}

	/**
	 * Shut down the thread pool executor. Calls normal shutdown of thread pool
	 * executor and awaits for termination. If not terminated, forcefully shuts down
	 * the executor after a timeout.
	 */
	public void shutDownThreadPoolExecutor() {

		if (ipScheduledService != null) {
			try {
				ipScheduledService.shutdown(); // disable new tasks from being submitted
				if (!ipScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
					// wait for termination for a timeout
					ipScheduledService.shutdownNow(); // cancel currently executing tasks

					if (!ipScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
						logger.log(Level.SEVERE, "Thread pool executor did not terminate");
					}
				}
			} catch (InterruptedException e) {
			}
		}
	}

	public static void setLogger() {
		IPScheduledThread.logger = Logger.getLogger(IPScheduledThread.class.getName());
	}
}