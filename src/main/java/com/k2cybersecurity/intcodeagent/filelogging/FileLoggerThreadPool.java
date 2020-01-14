package com.k2cybersecurity.intcodeagent.filelogging;

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
	 * A handler for rejected tasks that throws a
	 * {@code RejectedExecutionException}.
	 */
	public static class EventAbortPolicy implements RejectedExecutionHandler {
		/**
		 * Creates an {@code ValidationAbortPolicy}.
		 */
		public EventAbortPolicy() {
		}

		/**
		 * Always throws RejectedExecutionException.
		 *
		 * @param r the runnable task requested to be executed
		 * @param e the executor attempting to execute this task
		 * @throws RejectedExecutionException always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			// Just eat the rejection error.
		}
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
