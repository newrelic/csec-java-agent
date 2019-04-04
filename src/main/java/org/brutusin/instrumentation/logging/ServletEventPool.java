package org.brutusin.instrumentation.logging;


import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class ServletEventPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static ServletEventPool instance;
	

	private Map<Long, ServletInfo> requestMap;
	private Map<Long, Long> servletInfoReferenceRecord;
	
	private ServletEventPool() {
		LinkedBlockingQueue<Runnable> processQueue;
		this.setRequestMap(new ConcurrentHashMap<>());
		this.setServletInfoReferenceRecord(new ConcurrentHashMap<>());
		
		// load the settings
		int queueSize = 700;
		int maxPoolSize = 25;
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
	
	protected static ServletEventPool getInstance() {
		if (instance == null)
			instance = new ServletEventPool();
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


	public void processReceivedEvent(Object firstElement, Object request, ServletInfo servletInfo, String sourceString, long threadId) {
		try {
			this.executor.execute(new ServletEventProcessor(firstElement, request, servletInfo, sourceString, threadId));
		} catch (Exception e) {

		}
	}


	/**
	 * @return the requestMap
	 */
	public Map<Long, ServletInfo> getRequestMap() {
		return requestMap;
	}

	/**
	 * @param requestMap the requestMap to set
	 */
	public void setRequestMap(Map<Long, ServletInfo> requestMap) {
		this.requestMap = requestMap;
	}

	/**
	 * @return the servletInfoReferenceRecord
	 */
	public Map<Long, Long> getServletInfoReferenceRecord (){
		return servletInfoReferenceRecord;
	}

	/**
	 * @param servletInfoReferenceRecord the servletInfoReferenceRecord to set
	 */
	public void setServletInfoReferenceRecord(Map<Long, Long> servletInfoReferenceRecord) {
		this.servletInfoReferenceRecord = servletInfoReferenceRecord;
	}
	
	/**
	 * 
	 */
	public Long decrementServletInfoReference(Long threadId) {
		Long refCount = -1l;
		try {
			this.servletInfoReferenceRecord.put(threadId, this.servletInfoReferenceRecord.get(threadId) - 1);
			refCount = this.servletInfoReferenceRecord.get(threadId);
		} catch (Exception e) {}
		return refCount;
	}
	
	/**
	 * 
	 */
	public Long incrementServletInfoReference(Long threadId) {
		Long refCount = -1l;
		try {
			if ( this.servletInfoReferenceRecord.containsKey(threadId)) {
				this.servletInfoReferenceRecord.put(threadId, this.servletInfoReferenceRecord.get(threadId) + 1);
			}
			else {
				this.servletInfoReferenceRecord.put(threadId, 1l);
			}
			refCount = this.servletInfoReferenceRecord.get(threadId);
		} catch (Exception e) {}
		return refCount;
	}
}
