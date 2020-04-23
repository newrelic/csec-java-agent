package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPDoFilterMap;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.EventThreadPool.EventAbortPolicy;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DispatcherPool {

	/**
	 * Thread pool executor.
	 */
	private ThreadPoolExecutor executor;
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


	private static DispatcherPool instance;

	final int queueSize = 300;
	final int maxPoolSize = 3;
	final int corePoolSize = 2;
	final long keepAliveTime = 10;
	final TimeUnit timeUnit = TimeUnit.SECONDS;
	final boolean allowCoreThreadTimeOut = false;
	private static Object mutex = new Object();

	private DispatcherPool() {
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
							K2Instrumentator.JA_HEALTH_CHECK.incrementProcessedCount();
							future.get();
						}
					} catch (Throwable e) {
						K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
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

	public static DispatcherPool getInstance() {

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

	public void dispatchEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData,
			Object event, VulnerabilityCaseType vulnerabilityCaseType) {
		if(executor.isShutdown()){
			return;
		}
		this.executor.submit(new Dispatcher(httpRequestBean, metaData, event, vulnerabilityCaseType));
	}

	public void dispatchEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData,
							  Object event, VulnerabilityCaseType vulnerabilityCaseType, String currentGenericServletMethodName,
							  Object currentGenericServletInstance,
							  StackTraceElement[] stackTrace, StackTraceElement userClassElement, Boolean isCalledByUserCode) {
		if(executor.isShutdown()){
			return;
		}
		this.executor.submit(new Dispatcher(httpRequestBean, metaData, event, vulnerabilityCaseType, currentGenericServletMethodName,
				currentGenericServletInstance, stackTrace, userClassElement, isCalledByUserCode));
	}

	/**
	 * Specifically for reflected xss
	 * 
	 * @param httpRequestBean
	 * @param startTime
	 * @param exectionId
	 * @param sourceString
	 * @param reflectedXss
	 */
	public void dispatchEventRXSS(HttpRequestBean httpRequestBean, String sourceString, String exectionId,
								  long startTime, VulnerabilityCaseType reflectedXss, String currentGenericServletMethodName,
								  Object currentGenericServletInstance,
								  StackTraceElement[] stackTrace, StackTraceElement userClassElement, Boolean isCalledByUserCode) {
		if(executor.isShutdown()){
			return;
		}
		this.executor.submit(new Dispatcher(httpRequestBean, reflectedXss, sourceString, exectionId, startTime, currentGenericServletMethodName,
				currentGenericServletInstance, stackTrace, userClassElement, isCalledByUserCode));
	}

	public void shutDownThreadPoolExecutor() {

		if (executor != null) {
			try {
				executor.shutdown(); // disable new tasks from being submitted
				if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
					// wait for termination for a timeout
					executor.shutdownNow(); // cancel currently executing tasks

					if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
						logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
								DispatcherPool.class.getName());
					}
				}
			} catch (InterruptedException e) {
			}
		}

	}

}
