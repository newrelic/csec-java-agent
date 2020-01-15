package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.intcodeagent.logging.ServletEventPool.EventAbortPolicy;

import java.util.concurrent.*;

public class EventSendPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static EventSendPool instance;

	private EventSendPool() {
		// load the settings
		int queueSize = 1500;
		int maxPoolSize = 1;
		int corePoolSize = 1;
		long keepAliveTime = 60;

		TimeUnit timeUnit = TimeUnit.SECONDS;

		boolean allowCoreThreadTimeOut = false;

		executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit,
				new LinkedBlockingQueue<Runnable>(queueSize), new EventAbortPolicy()) {
			@Override
			protected void afterExecute(Runnable r, Throwable t) {
				if (r instanceof Future<?>) {
					try {
						Future<?> future = (Future<?>) r;
						if (future.isDone()) {
							future.get();
						}
					} catch (Exception e) {
					}
				}
				super.afterExecute(r, t);
			}
		};
		executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
		executor.setThreadFactory(new ThreadFactory() {
			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						"K2-EventSender");
			}
		});
	}

	/**
	 * @return the instance
	 */
	public static EventSendPool getInstance() {
		if (instance == null)
			instance = new EventSendPool();
		return instance;
	}

	public void sendEvent(String event) {
		executor.submit(new EventSender(event));
	}

}
