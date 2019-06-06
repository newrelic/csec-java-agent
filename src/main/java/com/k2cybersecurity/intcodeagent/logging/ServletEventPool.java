package com.k2cybersecurity.intcodeagent.logging;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.k2cybersecurity.intcodeagent.models.javaagent.ServletInfo;

public class ServletEventPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static ServletEventPool instance;

//	private Map<Long, ServletInfo> requestMap;

	private Map<Long, ConcurrentLinkedDeque<ExecutionMap>> requestMap;
	private Map<Long, ConcurrentLinkedDeque<EIDCount>> servletInfoReferenceRecord;

	/**
	 * @return the servletInfoReferenceRecord
	 */
	public Map<Long, ConcurrentLinkedDeque<EIDCount>> getServletInfoReferenceRecord() {
		return servletInfoReferenceRecord;
	}

	/**
	 * @param servletInfoReferenceRecord the servletInfoReferenceRecord to set
	 */
	public void setServletInfoReferenceRecord(Map<Long, ConcurrentLinkedDeque<EIDCount>> servletInfoReferenceRecord) {
		this.servletInfoReferenceRecord = servletInfoReferenceRecord;
	}

	private ServletEventPool() {
		LinkedBlockingQueue<Runnable> processQueue;
		this.setRequestMap(new ConcurrentHashMap<Long, ConcurrentLinkedDeque<ExecutionMap>>());
		this.setServletInfoReferenceRecord(new ConcurrentHashMap<Long, ConcurrentLinkedDeque<EIDCount>>());

		// load the settings
		int queueSize = 500;
		int maxPoolSize = 15;
		int corePoolSize = 1;
		long keepAliveTime = 2;

		TimeUnit timeUnit = TimeUnit.SECONDS;

		boolean allowCoreThreadTimeOut = false;
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

		};
		executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
		executor.setThreadFactory(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						"K2-Java-Agent-Servlet" + threadNumber.getAndIncrement());
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
		 * @param r the runnable task requested to be executed
		 * @param e the executor attempting to execute this task
		 * @throws RejectedExecutionException always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			System.out.println("Event Task " + r.toString() + " rejected from {} " + e.toString());
		}
	}

	public void processReceivedEvent(Object firstElement, Object request, ServletInfo servletInfo, String sourceString,
			long threadId) {
		try {
			this.executor
					.execute(new ServletEventProcessor(firstElement, request, servletInfo, sourceString, threadId));
		} catch (Exception e) {

		}
	}

	/**
	 * 
	 */
//	public synchronized Long decrementServletInfoReference(String threadEId) {
//		Long refCount = -1l;
//		try {
//			this.servletInfoReferenceRecord.put(threadEId, this.servletInfoReferenceRecord.get(threadEId) - 1);
//			refCount = this.servletInfoReferenceRecord.get(threadEId);
//		} catch (Exception e) {
//		}
//		return refCount;
//	}

	/**
	 * 
	 */
//	public synchronized Long incrementServletInfoReference(String threadEId) {
//		Long refCount = -1l;
//		try {
//			if (this.servletInfoReferenceRecord.containsKey(threadEId)) {
//				this.servletInfoReferenceRecord.put(threadEId, this.servletInfoReferenceRecord.get(threadEId) + 1);
//			} else {
//				this.servletInfoReferenceRecord.put(threadEId, 1l);
//			}
//			refCount = this.servletInfoReferenceRecord.get(threadEId);
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//		return refCount;
//	}

	/**
	 * @return the requestMap
	 */
	public Map<Long, ConcurrentLinkedDeque<ExecutionMap>> getRequestMap() {
		return requestMap;
	}

	/**
	 * @param requestMap the requestMap to set
	 */
	public void setRequestMap(Map<Long, ConcurrentLinkedDeque<ExecutionMap>> requestMap) {
		this.requestMap = requestMap;
	}

	public synchronized Long incrementServletInfoReference(long threadId, Integer executionId, boolean find) {
		Long refCount = -1l;
		try {
			if (find && this.servletInfoReferenceRecord.containsKey(threadId)) {
				EIDCount eidCount = EIDCount.find(executionId, this.servletInfoReferenceRecord.get(threadId));
				if (eidCount != null) {
					refCount = eidCount.increment();
				}
			} else if (!find && this.servletInfoReferenceRecord.containsKey(threadId)) {
				this.servletInfoReferenceRecord.get(threadId).add(new EIDCount(executionId, 1l));
				refCount = 1l;
			} else if (!find) {
				ConcurrentLinkedDeque<EIDCount> eidCounts = new ConcurrentLinkedDeque<>();
				eidCounts.add(new EIDCount(executionId, 1l));
				this.servletInfoReferenceRecord.put(threadId, eidCounts);
				refCount = 1l;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return refCount;
	}

	public Long decrementServletInfoReference(long threadId, Integer executionId, boolean find) {
		Long refCount = -1l;
		try {
			EIDCount eidCount = EIDCount.find(executionId, this.servletInfoReferenceRecord.get(threadId));
			if (eidCount != null) {
				refCount = eidCount.decrement();
				if (refCount <= 0) {
					this.requestMap.get(threadId).remove(new ExecutionMap(eidCount.getEid()));
					this.servletInfoReferenceRecord.get(threadId).remove(eidCount);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return refCount;
	}

}
