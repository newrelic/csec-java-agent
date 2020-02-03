package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

import java.net.URISyntaxException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HCSCHEDULEDTHREAD_;

public class HealthCheckScheduleThread {

	private static HealthCheckScheduleThread instance;

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static ScheduledExecutorService hcScheduledService;

	private HealthCheckScheduleThread() {
		Runnable runnable = new Runnable() {
			public void run() {

				try {
					// since tcp connection keep alive check is more than 2 hours
					// we send our custom object to check if connectino is still alive or not
					// this will be ignored by ic agent on the other side.

//						channel.write(ByteBuffer.wrap(new JAHealthCheck(AgentNew.JA_HEALTH_CHECK).toString().getBytes()));
					if (WSClient.getInstance().isOpen()) {
						WSClient.getInstance().send(new JAHealthCheck(K2Instrumentator.JA_HEALTH_CHECK).toString());
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
								logger.log(LogLevel.SEVERE, "Failed in WSock reconnection.",
										HealthCheckScheduleThread.class.getName());
								WSClient.reconnectWSClient();
								logger.log(LogLevel.DEBUG, "K2-JavaAgent re-installed successfully.",
										HealthCheckScheduleThread.class.getName());
							}
						} catch (URISyntaxException | InterruptedException e) {
							logger.log(LogLevel.SEVERE,
									"Error in WSock reconnection : " + e.getMessage() + " : " + e.getCause(), e,
									HealthCheckScheduleThread.class.getName());
						}
					}

				} catch (NullPointerException ex) {
					logger.log(LogLevel.WARNING, "No reference to Socket's OutputStream",
							HealthCheckScheduleThread.class.getName());
				} catch (Exception e) {
					logger.log(LogLevel.WARNING, "Error while trying to verify connection: ", e,
							HealthCheckScheduleThread.class.getName());
				}
			}
		};
		hcScheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						HCSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
			}
		});
		hcScheduledService.scheduleAtFixedRate(runnable, 5, 5, TimeUnit.MINUTES);
	}

	public static HealthCheckScheduleThread getInstance() {
		try {
			if (instance == null)
				instance = new HealthCheckScheduleThread();
			return instance;
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Error while starting: ", e, HealthCheckScheduleThread.class.getName());
		}
		throw null;
	}

	/**
	 * Shut down the thread pool executor. Calls normal shutdown of thread pool
	 * executor and awaits for termination. If not terminated, forcefully shuts down
	 * the executor after a timeout.
	 */
	public void shutDownThreadPoolExecutor() {

		if (hcScheduledService != null) {
			try {
				hcScheduledService.shutdown(); // disable new tasks from being submitted
				if (!hcScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
					// wait for termination for a timeout
					hcScheduledService.shutdownNow(); // cancel currently executing tasks

					if (!hcScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
						logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
								HealthCheckScheduleThread.class.getName());
					}else {
						logger.log(LogLevel.INFO, "Thread pool executor terminated",
								HealthCheckScheduleThread.class.getName());
					}
				}
			} catch (InterruptedException e) {
			}
		}
	}
}