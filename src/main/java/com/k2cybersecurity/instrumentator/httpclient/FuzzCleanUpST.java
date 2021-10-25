package com.k2cybersecurity.instrumentator.httpclient;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.util.concurrent.*;

public class FuzzCleanUpST {

    private ScheduledExecutorService executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static FuzzCleanUpST instance;

    private static final Object mutex = new Object();

    private FuzzCleanUpST() {
        executor = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread worker = new Thread(Thread.currentThread().getThreadGroup(), r,
                        "fuzz-clean-up-scheduler");
                worker.setDaemon(true);
                return worker;
            }
        });
    }

    public void scheduleCleanUp(String path) {
        executor.schedule(new FuzzCleanUpTask(path), 10, TimeUnit.SECONDS);
    }

    public static FuzzCleanUpST getInstance() {

        if (instance == null) {
            synchronized (mutex) {
                if (instance == null) {
                    instance = new FuzzCleanUpST();
                }
                return instance;
            }
        }
        return instance;
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
                                RestRequestThreadPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }
}

class FuzzCleanUpTask implements Callable<Boolean> {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String UNABLE_TO_DO_FUZZ_CLEANUP = "Unable to do fuzz cleanup :";

    private String path;

    public FuzzCleanUpTask(String path) {
        this.path = path;
    }

    @Override
    public Boolean call() {
        try {
            return FileUtils.deleteQuietly(new File(this.path));
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, UNABLE_TO_DO_FUZZ_CLEANUP + this.path, e,
                    RestRequestThreadPool.class.getName());
        }
        return false;
    }
}
