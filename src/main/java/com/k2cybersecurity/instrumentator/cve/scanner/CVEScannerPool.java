package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.EventThreadPool.EventAbortPolicy;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;

import java.nio.file.Paths;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class CVEScannerPool {

    public static final String ALL_PERMISSIONS = "rwxrwxrwx";
    /**
     * Thread pool executor.
     */
    private ThreadPoolExecutor executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private final static Object lock = new Object();
    private static CVEScannerPool instance;

    final int queueSize = 10;
    final int maxPoolSize = 1;
    final int corePoolSize = 1;
    final long keepAliveTime = 20;
    final TimeUnit timeUnit = TimeUnit.SECONDS;
    final boolean allowCoreThreadTimeOut = false;

    private CVEPackageInfo packageInfo;

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

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
    }

    public static CVEScannerPool getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new CVEScannerPool();
                    return instance;
                }
            }
        }
        return instance;
    }

    public void dispatchScanner(String nodeId, String kind, String id, boolean isEnvScan) {
        synchronized (lock) {
            if (isEnvScan && AgentUtils.getInstance().isCveEnvScanCompleted()) {
                return;
            }
            if (isEnvScan) {
                AgentUtils.getInstance().setCveEnvScanCompleted(true);
            }
            if (executor.isShutdown()) {
                return;
            }
            CVEPackageInfo packageInfo = CVEComponentsService.getCVEPackageInfo();

//            new File(osVariables.getCvePackageBaseDir()).mkdirs();
            CommonUtils.forceMkdirs(Paths.get(osVariables.getCvePackageBaseDir()), ALL_PERMISSIONS);

            switch (osVariables.getOs()) {
                case IAgentConstants.LINUX:
                    this.executor.submit(new CVEServiceLinux(nodeId, kind, id, packageInfo, isEnvScan));
                    break;
                case IAgentConstants.MAC:
                    this.executor.submit(new CVEServiceMac(nodeId, kind, id, packageInfo, isEnvScan));
                    break;
                case IAgentConstants.WINDOWS:
                    this.executor.submit(new CVEServiceWindows(nodeId, kind, id, packageInfo, isEnvScan));
                    break;
            }
        }
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
    }

    /**
     * Shut down the thread pool executor. Calls normal shutdown of thread pool
     * executor and awaits for termination. If not terminated, forcefully shuts down
     * the executor after a timeout.
     */
    public void shutDownThreadPoolExecutor() {

        if (executor != null) {
            try {
                executor.shutdown(); // disable new tasks from being submitted
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    executor.shutdownNow(); // cancel currently executing tasks

                    if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.FATAL, "Thread pool executor did not terminate",
                                CVEScannerPool.class.getName());
                    } else {
                        logger.log(LogLevel.INFO, "Thread pool executor terminated",
                                CVEScannerPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }

    public CVEPackageInfo getPackageInfo() {
        return packageInfo;
    }

    public void setPackageInfo(CVEPackageInfo packageInfo) {
        this.packageInfo = packageInfo;
    }


}
