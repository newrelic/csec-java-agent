package org.brutusin.instrumentation.logging;

import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class EventThreadPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static EventThreadPool instance;
	
	private StringBuffer eventBuffer;

	private EventThreadPool() {
		LinkedBlockingQueue<Runnable> processQueue;

		// load the settings
		int queueSize = 700;
		int maxPoolSize = 15;
		int corePoolSize = 1;
		long keepAliveTime = 2;

		TimeUnit timeUnit = TimeUnit.SECONDS;

		boolean allowCoreThreadTimeOut = false;

		if (queueSize == 0) {
			processQueue = new LinkedBlockingQueue<>();
		} else {
			processQueue = new LinkedBlockingQueue<>(queueSize);
		}

		executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
				new EventAbortPolicy()) {

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
		this.eventBuffer = new StringBuffer();
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

	protected static EventThreadPool getInstance() {
		if (instance == null)
			instance = new EventThreadPool();
		return instance;
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
		 * @param r
		 *            the runnable task requested to be executed
		 * @param e
		 *            the executor attempting to execute this task
		 * @throws RejectedExecutionException
		 *             always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			System.out.println("Event Task " + r.toString() + " rejected from {} " + e.toString());
		}
	}

	public void processReceivedEvent(Object source, Object[] arg, String executionId, StackTraceElement[] stackTrace) {
		try {
			this.executor.execute(new ProcessorThread(source, arg, executionId, stackTrace));
		} catch (Exception e) {

		}
	}
	
	protected boolean isQueueEmpty() {
		return this.executor.getQueue().isEmpty();
	}

	/**
	 * @return the eventBuffer
	 */
	public StringBuffer getEventBuffer() {
		return eventBuffer;
	}
	
	/**
	 * @return the eventBuffer
	 */
	public StringBuffer renewEventBuffer() {
		return this.eventBuffer = new StringBuffer();
	}

}
