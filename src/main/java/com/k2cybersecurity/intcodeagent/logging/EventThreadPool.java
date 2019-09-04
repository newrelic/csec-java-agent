package com.k2cybersecurity.intcodeagent.logging;

import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

public class EventThreadPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static EventThreadPool instance;
	private static short MAX_BLOCKING_QUEUE_SIZE = 3000;
	private static Object mutex = new Object();
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private StringBuffer eventBuffer;
	private LinkedBlockingQueue<Object> eventQueue = new LinkedBlockingQueue<>(MAX_BLOCKING_QUEUE_SIZE);
//	private AsynchronousSocketChannel channel;

	private boolean triedReconnect = false;

	final int queueSize = 300;
	final int maxPoolSize = 3;
	final int corePoolSize = 1;
	final long keepAliveTime = 10;
	final TimeUnit timeUnit = TimeUnit.SECONDS;
	final boolean allowCoreThreadTimeOut = false;

	private EventThreadPool() {
		LinkedBlockingQueue<Runnable> processQueue;
		// load the settings
		processQueue = new LinkedBlockingQueue<>(queueSize);
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

			@Override
			protected void beforeExecute(Thread t, Runnable r) {
				LoggingInterceptor.JA_HEALTH_CHECK.incrementProcessedCount();
				super.beforeExecute(t, r);
			}

		};
		this.eventBuffer = new StringBuffer();
		executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
		executor.setThreadFactory(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						IAgentConstants.K2_JAVA_AGENT + threadNumber.getAndIncrement());
			}
		});
	}

	public void shutDownThreadPoolExecutor() {

		if (executor != null) {
			try {
				executor.shutdown(); // disable new tasks from being submitted
				if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
					// wait for termination for a timeout
					executor.shutdownNow(); // cancel currently executing tasks

					if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
						logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate", EventThreadPool.class.getName());
					}
				}
			} catch (InterruptedException e) {
			}
		}

	}

	protected static EventThreadPool getInstance() {

		if (instance == null) {
			synchronized (mutex) {
				if (instance == null) {
					instance = new EventThreadPool();
				}
				return instance;
			}
		}
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
		 * @param r the runnable task requested to be executed
		 * @param e the executor attempting to execute this task
		 * @throws RejectedExecutionException always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			LoggingInterceptor.JA_HEALTH_CHECK.incrementDropCount();
			LoggingInterceptor.JA_HEALTH_CHECK.incrementProcessedCount();
//			logger.log(LogLevel.FINE,"Event Task " + r.toString() + " rejected from  " + e.toString(), EventThreadPool.class.getName());
		}
	}

	public void processReceivedEvent(Object source, Object[] arg, Long executionId, StackTraceElement[] stackTrace,
			long tId, String sourceString, long preProcessingTime) {
		try {
			this.executor.execute(
					new ProcessorThread(source, arg, executionId, stackTrace, tId, sourceString, preProcessingTime));
		} catch (RejectedExecutionException rejected) {
			logger.log(LogLevel.INFO, "Rejected to process Event At: " + this.executor.getQueue().size() + ": " +rejected, EventThreadPool.class.getName());
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Error in processReceivedEvent: "+ e, EventThreadPool.class.getName());
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

	public LinkedBlockingQueue<Object> getEventQueue() {
		return eventQueue;
	}

	// TODO: remove this getter
	protected ThreadPoolExecutor getExecutor() {
		return executor;
	}

	public boolean triedReconnect() {
		return triedReconnect;
	}

	public void setTriedReconnect(boolean triedReconnect) {
		this.triedReconnect = triedReconnect;
	}

}
