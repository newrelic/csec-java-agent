package com.k2cybersecurity.intcodeagent.filelogging;

import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.k2cybersecurity.intcodeagent.logging.ServletEventPool.EventAbortPolicy;

public class FileLoggerThreadPool {
	private ThreadPoolExecutor executor;

	private static FileLoggerThreadPool instance;

	private FileLoggerThreadPool() {
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
						"Logger");
			}
		});
	}

	/**
	 * @return the instance
	 */
	public static FileLoggerThreadPool getInstance() {
		if (instance == null)
			instance = new FileLoggerThreadPool();
		return instance;
	}

	public void log(LogLevel logLevel, String event, String logSourceClassName) {
		executor.submit(new LogWriter(logLevel, event, logSourceClassName));
	}
}
