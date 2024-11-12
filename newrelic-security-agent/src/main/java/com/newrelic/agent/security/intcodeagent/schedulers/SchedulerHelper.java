package com.newrelic.agent.security.intcodeagent.schedulers;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.intcodeagent.filelogging.LogFileHelper;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;

import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class SchedulerHelper {

    public static final String IAST_TRIGGER = "IastTrigger";
    private final ScheduledExecutorService commonExecutor;

    private SchedulerHelper() {
        commonExecutor = Executors.newScheduledThreadPool(1, new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(Thread.currentThread().getThreadGroup(), r,
                        IAgentConstants.SCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    private static final class InstanceHolder {
        static final SchedulerHelper instance = new SchedulerHelper();
    }

    public static SchedulerHelper getInstance() {
        return InstanceHolder.instance;
    }

    private final Map<String, ScheduledFuture<?>> scheduledFutureMap = new ConcurrentHashMap<>();

    public ScheduledFuture<?> scheduleIastTrigger(Runnable runnable, long initialDelay, TimeUnit unit) {
        if(scheduledFutureMap.containsKey(IAST_TRIGGER)){
            ScheduledFuture<?> currentFuture = scheduledFutureMap.get(IAST_TRIGGER);
            currentFuture.cancel(false);
        }
        ScheduledFuture<?> future = commonExecutor.schedule(runnable, initialDelay, unit);
        scheduledFutureMap.put(IAST_TRIGGER, future);
        return future;
    }

    public ScheduledFuture<?> scheduleHealthCheck(Runnable command,
                                               long initialDelay,
                                               long period,
                                               TimeUnit unit){
        ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, initialDelay, period, unit);
        scheduledFutureMap.put("HC", future);
        return future;
    }

    public ScheduledFuture<?> scheduleTmpFileCleanup(Runnable command,
                                                  long initialDelay,
                                                  long period,
                                                  TimeUnit unit){
        ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, initialDelay, period, unit);
        scheduledFutureMap.put("FileCleaner", future);
        return future;
    }

    public ScheduledFuture<?> scheduleLowSeverityFilterCleanup(Runnable command,
                                               long initialDelay,
                                               long period,
                                               TimeUnit unit){
        ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, initialDelay, period, unit);
        scheduledFutureMap.put("low-severity-hook-filter-cleanup", future);
        return future;
    }

    public ScheduledFuture<?> scheduleApplicationRuntimeErrorPosting(Runnable command,
                                                               long initialDelay,
                                                               long period,
                                                               TimeUnit unit){
        ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, initialDelay, period, unit);
        scheduledFutureMap.put("application-runtime-error-posting", future);
        return future;
    }

    public ScheduledFuture<?> scheduleDailyLogRollover(Runnable command) {

        if(LogFileHelper.isDailyRollover()) {
            int period = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_LOG_DAILY_ROLLOVER_PERIOD, 24);
            ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, period, period, TimeUnit.HOURS);
            scheduledFutureMap.put("daily-log-rollover", future);
            return future;
        }
        return null;
    }

    public void scheduleURLMappingPosting(Runnable runnable) {
        if(scheduledFutureMap.containsKey(IAgentConstants.JSON_SEC_APPLICATION_URL_MAPPING)){
            ScheduledFuture<?> future = scheduledFutureMap.get(IAgentConstants.JSON_SEC_APPLICATION_URL_MAPPING);
            future.cancel(false);
        }
        ScheduledFuture<?> future = commonExecutor.schedule(runnable, 60, TimeUnit.SECONDS);
        scheduledFutureMap.put(IAgentConstants.JSON_SEC_APPLICATION_URL_MAPPING, future);
    }

    public void scheduleSampling(Runnable runnable, long initialDelay, long delay, TimeUnit unit) {
        if(AgentConfig.getInstance().getAgentMode().getIastScan().getMonitoring()) {
            ScheduledFuture<?> future = commonExecutor.scheduleAtFixedRate(runnable, initialDelay, delay, unit);
            scheduledFutureMap.put("sampling", future);
        }
    }
}
