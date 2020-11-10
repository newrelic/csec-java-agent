package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.EventThreadPool.EventAbortPolicy;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class CVEScannerPool {

	/**
	 * Thread pool executor.
	 */
	private ThreadPoolExecutor executor;
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static CVEScannerPool instance;

	final int queueSize = 10;
	final int maxPoolSize = 1;
	final int corePoolSize = 1;
	final long keepAliveTime = 20;
	final TimeUnit timeUnit = TimeUnit.SECONDS;
	final boolean allowCoreThreadTimeOut = false;

	private CVEScannerPool() {
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
						future.isDone();
					} catch (Throwable e) {
					}
				}
				super.afterExecute(r, t);
			}

			@Override
			protected void beforeExecute(Thread t, Runnable r) {
				super.beforeExecute(t, r);
			}

		};
		executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
		executor.setThreadFactory(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						"K2-local-cve-service-" + threadNumber.getAndIncrement());
			}
		});

		File cveTar = new File(CVEService.TMP_LOCALCVESERVICE_TAR);
		if (FileUtils.deleteQuietly(cveTar)) {
			logger.log(LogLevel.INFO, "Stale CVE service bundle deleted.", CVEScannerPool.class.getName());
		} else {
			logger.log(LogLevel.WARNING, "Unable to delete stale CVE service bundle.", CVEScannerPool.class.getName());
		}
	}

	public static CVEScannerPool getInstance() {

		if (instance == null) {
			instance = new CVEScannerPool();
			return instance;
		}
		return instance;
	}

	public void dispatchScanner( String nodeId, String kind, String id, boolean downloadTarBundle, boolean isEnvScan) {
		if (executor.isShutdown()) {
			return;
		}
		this.executor.submit(new CVEService(nodeId, kind, id, downloadTarBundle, isEnvScan));
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
								CVEScannerPool.class.getName());
					}
				}
			} catch (InterruptedException e) {
			}
		}

	}

}
