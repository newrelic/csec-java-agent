package com.newrelic.agent.security.intcodeagent.filelogging;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.LogMessage;
import com.newrelic.agent.security.intcodeagent.properties.K2JALogProperties;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.io.IOException;
import java.util.concurrent.*;

public class FileLoggerThreadPool {
    private ThreadPoolExecutor executor;

    private static FileLoggerThreadPool instance;

    private boolean isLoggingActive = true;

    private boolean isInitLoggingActive = true;

    protected final int maxfilesize;

    protected final int maxfiles;

    protected boolean isLoggingToStdOut = false;

    private FileLoggerThreadPool() throws IOException {
        // load the settings
        int queueSize = 15000;
        int maxPoolSize = 1;
        int corePoolSize = 1;
        long keepAliveTime = 600;
        maxfiles = Math.max(K2JALogProperties.maxfiles, LogFileHelper.logFileCount());
        maxfilesize = LogFileHelper.logFileLimit()*1024;

        TimeUnit timeUnit = TimeUnit.SECONDS;

        boolean allowCoreThreadTimeOut = false;
        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit,
                new LinkedBlockingQueue<Runnable>(queueSize), new EventAbortPolicy()) {
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof Future<?>) {
                    try {
                        Future<?> future = (Future<?>) r;
                        if (future.isDone()) {
                            future.get();
                        }
                    } catch (Throwable ignored) {}
                }
                super.afterExecute(r, t);
            }
        };
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        executor.setThreadFactory(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r, "NR-CSEC-Logger");
                t.setDaemon(true);
                return t;
            }
        });
        try {
            if(LogFileHelper.isLoggingToStdOut()){
                this.isLoggingToStdOut = true;
            }
        } catch (NumberFormatException e){}

    }


    public void shutDownThreadPoolExecutor() {

        if (executor != null) {
            try {
                executor.shutdown(); // disable new tasks from being submitted
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    executor.shutdownNow(); // cancel currently executing tasks
                }
            } catch (InterruptedException e) {
            }
        }

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
            // Just eat the rejection error.
        }
    }

    /**
     * @return the instance
     */
    public static FileLoggerThreadPool getInstance() {
        if (instance == null)
            try {
                instance = new FileLoggerThreadPool();
            } catch (IOException e) {
            }
        return instance;
    }

    public void log(LogLevel logLevel, String event, String logSourceClassName) {
        if (logLevel.getLevel() == 1 || logLevel.getLevel() > LogWriter.defaultLogLevel) {
            return;
        }
        executor.submit(new LogWriter(logLevel, event, logSourceClassName, Thread.currentThread().getName()));
    }

    public void log(LogLevel logLevel, String event, Throwable throwableEvent, String logSourceClassName) {
        if (logLevel.getLevel() == 1 || logLevel.getLevel() > LogWriter.defaultLogLevel) {
            return;
        }
        executor.submit(new LogWriter(logLevel, event, throwableEvent, logSourceClassName, Thread.currentThread().getName()));
    }

    public void logInit(LogLevel logLevel, String event, String logSourceClassName) {
        postLogMessage(logLevel, event, null, logSourceClassName);
        if (logLevel.getLevel() == 1 || logLevel.getLevel() > InitLogWriter.defaultLogLevel) {
            return;
        }
        if(!isLoggingToStdOut) {
            executor.submit(new InitLogWriter(logLevel, event, logSourceClassName, Thread.currentThread().getName()));
        }
        log(logLevel, event, logSourceClassName);
    }

    public void logInit(LogLevel logLevel, String event, Throwable throwableEvent, String logSourceClassName) {
        postLogMessage(logLevel, event, throwableEvent, logSourceClassName);
        if (logLevel.getLevel() == 1 || logLevel.getLevel() > InitLogWriter.defaultLogLevel) {
            return;
        }
        if(!isLoggingToStdOut) {
            executor.submit(new InitLogWriter(logLevel, event, throwableEvent, logSourceClassName, Thread.currentThread().getName()));
        }
        log(logLevel, event, throwableEvent, logSourceClassName);
    }

    public void postLogMessageIfNecessary(LogLevel logLevel, String event, Throwable exception, String caller) {
        if (logLevel.getLevel() > LogLevel.WARNING.getLevel()) {
            return;
        }
        postLogMessage(logLevel, event, exception, caller);
    }

    private LogMessage postLogMessage(LogLevel logLevel, String messageString, Throwable exception, String caller) {
        LogMessage message = new LogMessage(logLevel.name(), messageString, caller, exception, AgentInfo.getInstance().getLinkingMetadata());
        if (logLevel.getLevel() <= LogLevel.WARNING.getLevel()) {
            AgentUtils.getInstance().addStatusLogMostRecentErrors(JsonConverter.toJSON(message));
        }
        EventSendPool.getInstance().sendEvent(message);
        return message;
    }

    public boolean isLoggingActive() {
        return isLoggingActive;
    }

    public void setLoggingActive(boolean loggingActive) {
        isLoggingActive = loggingActive;
    }

    public boolean isInitLoggingActive() {
        return isInitLoggingActive;
    }

    public void setInitLoggingActive(boolean initLoggingActive) {
        isInitLoggingActive = initLoggingActive;
    }

    public boolean isLogLevelEnabled(LogLevel logLevel) {
        return (logLevel.getLevel() >= LogWriter.defaultLogLevel);
    }
}
