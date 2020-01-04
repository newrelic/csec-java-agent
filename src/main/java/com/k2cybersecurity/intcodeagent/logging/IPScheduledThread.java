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

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

public class IPScheduledThread {

	private static IPScheduledThread instance;

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

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

//						channel.write(ByteBuffer.wrap(new JAHealthCheck(AgentNew.JA_HEALTH_CHECK).toString().getBytes()));
						if (WSClient.getInstance().isOpen()) {
							WSClient.getInstance()
									.send(new JAHealthCheck(K2Instrumentator.JA_HEALTH_CHECK).toString());
							K2Instrumentator.JA_HEALTH_CHECK.setEventDropCount(0);
							K2Instrumentator.JA_HEALTH_CHECK.setEventProcessed(0);
							K2Instrumentator.JA_HEALTH_CHECK.setEventSentCount(0);
						} else {
							try {
								WSClient.reconnectWSClient();
								TimeUnit.SECONDS.sleep(5);
								if (WSClient.getInstance().isOpen()) {
									WSClient.getInstance()
											.send(new JAHealthCheck(K2Instrumentator.JA_HEALTH_CHECK).toString());
									K2Instrumentator.JA_HEALTH_CHECK.setEventDropCount(0);
								} else {
									logger.log(LogLevel.SEVERE, "Failed in WSock reconnection.", IPScheduledThread.class.getName());
								}
							} catch (URISyntaxException | InterruptedException e) {
								logger.log(LogLevel.SEVERE,
										"Error in WSock reconnection : " + e.getMessage() + " : " + e.getCause(), IPScheduledThread.class.getName());
							}
						}

					} catch (NullPointerException ex) {
						logger.log(LogLevel.WARNING, "No reference to Socket's OutputStream", IPScheduledThread.class.getName());
					} catch (Exception e) {
						logger.log(LogLevel.WARNING, "Error while trying to verify connection: ", e, IPScheduledThread.class.getName());
					}
					if (hostip == null || hostip.equals(StringUtils.EMPTY)) {
						logger.log(LogLevel.DEBUG, "Host ip not found", IPScheduledThread.class.getName());
					} else if (!K2Instrumentator.hostip.equals(hostip)) {
						K2Instrumentator.hostip = hostip.trim();
						WSClient.reconnectWSClient();
						logger.log(LogLevel.DEBUG, "K2-JavaAgent re-installed successfully coz of IP change.", IPScheduledThread.class.getName());
					} else if (!WSClient.getInstance().isOpen()) {
						WSClient.reconnectWSClient();
						logger.log(LogLevel.DEBUG, "K2-JavaAgent re-installed successfully.", IPScheduledThread.class.getName());
					}
				} catch (Exception e) {
					logger.log(LogLevel.WARNING, "Error in IPScheduledThread : ", e, IPScheduledThread.class.getName());
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
			logger.log(LogLevel.WARNING, "Error while starting: ", e, IPScheduledThread.class.getName());
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
						logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate", IPScheduledThread.class.getName());
					}
				}
			} catch (InterruptedException e) {
			}
		}
	}
}