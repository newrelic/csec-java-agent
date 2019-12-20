package com.k2cybersecurity.intcodeagent.filelogging;

import com.k2cybersecurity.intcodeagent.logging.ServletEventPool.EventAbortPolicy;

import java.io.IOException;
import java.util.concurrent.*;

public class FileLoggerThreadPool {
	private ThreadPoolExecutor executor;

	private static FileLoggerThreadPool instance;

	private String updatedFileName;

	private int logFileCounter = 0;

	private FileLoggerThreadPool() throws IOException {
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
				return new Thread(Thread.currentThread().getThreadGroup(), r, "Logger");
			}
		});
	}

	/**
	 * @return the instance
	 */
	public static FileLoggerThreadPool getInstance() {
		if (instance == null)
			try {
				instance = new FileLoggerThreadPool();
			} catch (IOException e) {
			}
		return instance;
	}

	public void log(LogLevel logLevel, String event, String logSourceClassName) {
		executor.submit(new LogWriter(logLevel, event, logSourceClassName));
	}

	public void log(LogLevel logLevel, String event, Throwable throwableEvent, String logSourceClassName) {
		executor.submit(new LogWriter(logLevel, event, throwableEvent, logSourceClassName));
	}
}
