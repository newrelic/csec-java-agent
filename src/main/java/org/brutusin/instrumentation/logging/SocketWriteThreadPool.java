package org.brutusin.instrumentation.logging;

import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class SocketWriteThreadPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static SocketWriteThreadPool instance;

	private SocketWriteThreadPool() {
		LinkedBlockingQueue<Runnable> processQueue;

		// load the settings
		int queueSize = 500;
		int maxPoolSize = 50;
		int corePoolSize = 15;
		long keepAliveTime = 5;

		TimeUnit timeUnit = TimeUnit.SECONDS;

		boolean allowCoreThreadTimeOut = false;

		if (queueSize == 0) {
			processQueue = new LinkedBlockingQueue<>();
		} else {
			processQueue = new LinkedBlockingQueue<>(queueSize);
		}

		executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
				new ValidationAbortPolicy()) {

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
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						"K2-Java-Agent-" + threadNumber.getAndIncrement());
			}
		});
	}

	protected static SocketWriteThreadPool getInstance() {
		if (instance == null)
			instance = new SocketWriteThreadPool();
		return instance;
	}

	/**
	 * A handler for rejected tasks that throws a
	 * {@code RejectedExecutionException}.
	 */
	public static class ValidationAbortPolicy implements RejectedExecutionHandler {
		/**
		 * Creates an {@code ValidationAbortPolicy}.
		 */
		public ValidationAbortPolicy() {
		}

		/**
		 * Always throws RejectedExecutionException.
		 *
		 * @param r
		 *            the runnable task requested to be executed
		 * @param e
		 *            the executor attempting to execute this task
		 * @throws RejectedExecutionException
		 *             always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			System.out.println("Event Task " + r.toString() + " rejected from {} " + e.toString());
			throw new RejectedExecutionException("Task " + r.toString() + " rejected from " + e.toString());
		}
	}

	public void processReceivedEvent(Object source, Object[] arg, String executionId, StackTraceElement[] stackTrace) {
		try {
			this.executor.execute(new ProcessorThread(source, arg, executionId, stackTrace));
		} catch (Exception e) {

		}
	}

}
