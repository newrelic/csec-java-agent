package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.intcodeagent.logging.EventThreadPool.EventAbortPolicy;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;

import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DispatcherPool {

	/**
	 * Thread pool executor.
	 */
	private ThreadPoolExecutor executor;

	private static DispatcherPool instance;

	private Map<String, List<JavaAgentEventBean>> lazyEvents;

	final int queueSize = 300;
	final int maxPoolSize = 3;
	final int corePoolSize = 1;
	final long keepAliveTime = 10;
	final TimeUnit timeUnit = TimeUnit.SECONDS;
	final boolean allowCoreThreadTimeOut = false;
	private static Object mutex = new Object();

	private DispatcherPool() {
		lazyEvents = new ConcurrentHashMap<>();
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
				// TODO increment event proccessed count
				super.beforeExecute(t, r);
			}

		};
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

	protected static DispatcherPool getInstance() {

		if (instance == null) {
			synchronized (mutex) {
				if (instance == null) {
					instance = new DispatcherPool();
				}
				return instance;
			}
		}
		return instance;
	}

	public void dispatchEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData, StackTraceElement[] trace,
			Object event, VulnerabilityCaseType vulnerabilityCaseType) {
		this.executor.submit(new Dispatcher(httpRequestBean, metaData, trace, event, vulnerabilityCaseType));
	}

	public void dispatchEvent(StackTraceElement[] trace, Object event, VulnerabilityCaseType vulnerabilityCaseType,
			Boolean sendToBuffer) {
		this.executor.submit(new Dispatcher(trace, event, vulnerabilityCaseType, sendToBuffer));
	}

	public void dispatchAppInfo(Object event, VulnerabilityCaseType vulnerabilityCaseType) {
		this.executor.submit(new Dispatcher(event, vulnerabilityCaseType));
	}

	/**
	 * Specifically for reflected xss
	 * 
	 * @param httpRequestBean
	 * @param trace
	 * @param startTime
	 * @param exectionId
	 * @param sourceString
	 * @param reflectedXss
	 */
	public void dispatchEvent(HttpRequestBean httpRequestBean, String sourceString, String exectionId, long startTime,
			StackTraceElement[] trace, VulnerabilityCaseType reflectedXss) {
		this.executor.submit(new Dispatcher(httpRequestBean, trace, reflectedXss, sourceString, exectionId, startTime));
	}

	public void dispatchEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData, StackTraceElement[] trace,
			FileOperationalBean event, FileIntegrityBean fbean, VulnerabilityCaseType vulnerabilityCaseType) {
		this.executor.submit(new Dispatcher(httpRequestBean, metaData, trace, event, fbean, vulnerabilityCaseType));
	}

	/**
	 * @return the lazyEvents
	 */
	public Map<String, List<JavaAgentEventBean>> getLazyEvents() {
		return lazyEvents;
	}

	/**
	 * @param lazyEvents the lazyEvents to set
	 */
	public void setLazyEvents(Map<String, List<JavaAgentEventBean>> lazyEvents) {
		this.lazyEvents = lazyEvents;
	}
}
