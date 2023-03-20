package com.newrelic.agent.security.intcodeagent.logging;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.httpclient.RestClient;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JAHealthCheck;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.text.StringSubstitutor;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.lang.reflect.Method;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class HealthCheckScheduleThread {

    public static final String STATUS_TIMESTAMP = "timestamp";
    public static final String CAN_T_WRITE_STATUS_LOG_FILE_S_REASON_S = "Can't write status log file : %s , reason : %s ";
    public static final String LAST_5_ERRORS = "last-5-errors";
    public static final String LAST_5_HC = "last-5-hc";
    public static final String K_2_AGENT_STATUS_LOG = "java-security-collector-status-%s.log";
    public static final String LATEST_PROCESS_STATS = "latest-process-stats";
    public static final String LATEST_SERVICE_STATS = "latest-service-stats";
    public static final String VALIDATOR_SERVER_STATUS = "validator-server-status";
    public static final String ENFORCED_POLICY = "enforced-policy";

    public static final String WEBSOCKET = "websocket";
    public static final String SEPARATOR = ": ";
    public static final String CAN_T_CREATE_STATUS_LOG_FILE = "Can't create status log file!!!";
    private static HealthCheckScheduleThread instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static ScheduledExecutorService hcScheduledService;

    private ScheduledFuture future;

    private static boolean isStatusLoggingActive = true;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private Runnable runnable = new Runnable() {
        public void run() {

            try {
                // since tcp connection keep alive check is more than 2 hours
                // we send our custom object to check if connection is still alive or not
                // this will be ignored by ic agent on the other side.

                AgentInfo.getInstance().getJaHealthCheck().setStats(populateJVMStats());
                AgentInfo.getInstance().getJaHealthCheck().setServiceStatus(getServiceStatus());

                if (!AgentInfo.getInstance().isAgentActive()) {
                    return;
                }

                AgentInfo.getInstance().getJaHealthCheck().setDsBackLog(RestRequestThreadPool.getInstance().getQueueSize());
                AgentUtils.getInstance().getStatusLogMostRecentHCs().add(AgentInfo.getInstance().getJaHealthCheck().toString());
//						channel.write(ByteBuffer.wrap(new JAHealthCheck(AgentNew.JA_HEALTH_CHECK).toString().getBytes()));
                if (WSClient.getInstance().isOpen()) {
                    WSClient.getInstance().send(JsonConverter.toJSON(new JAHealthCheck(AgentInfo.getInstance().getJaHealthCheck())));
                    AgentInfo.getInstance().getJaHealthCheck().setEventDropCount(0);
                    AgentInfo.getInstance().getJaHealthCheck().setEventProcessed(0);
                    AgentInfo.getInstance().getJaHealthCheck().setEventSentCount(0);
                    AgentInfo.getInstance().getJaHealthCheck().setHttpRequestCount(0);
                    AgentInfo.getInstance().getJaHealthCheck().setExitEventSentCount(0);
                }

            } catch (NullPointerException ex) {
                logger.log(LogLevel.WARNING, "No reference to Socket's OutputStream",
                        HealthCheckScheduleThread.class.getName());
            } catch (Throwable e) {
                logger.log(LogLevel.WARNING, "Error while trying to verify connection: ", e,
                        HealthCheckScheduleThread.class.getName());
            } finally {
                writeStatusLogFile();
            }
        }
    };

    private HealthCheckScheduleThread() {
        hcScheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        IAgentConstants.HCSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
            }
        });
    }

    public void scheduleNewTask() {
        future = hcScheduledService.scheduleAtFixedRate(runnable, 1, 5, TimeUnit.MINUTES);
    }

    public boolean cancelTask(boolean forceCancel) {
        if (future == null) {
            return true;
        }
        if (future != null && (forceCancel || future.isDone() || future.getDelay(TimeUnit.MINUTES) > 5)) {
            logger.log(LogLevel.INFO, "Cancel current task of HealthCheck Schedule", HealthCheckScheduleThread.class.getName());
            future.cancel(true);
            return true;
        }
        return false;
    }

    private void writeStatusLogFile() {
        File statusLog = new File(osVariables.getSnapshotDir(), String.format(K_2_AGENT_STATUS_LOG, AgentInfo.getInstance().getApplicationUUID()));
        try {
            FileUtils.deleteQuietly(statusLog);
            if (statusLog.createNewFile()) {
                Map<String, String> substitutes = AgentUtils.getInstance().getStatusLogValues();
                substitutes.put(STATUS_TIMESTAMP, Instant.now().toString());
                substitutes.put(LATEST_PROCESS_STATS, AgentInfo.getInstance().getJaHealthCheck().getStats().keySet().stream()
                        .map(key -> key + SEPARATOR + AgentInfo.getInstance().getJaHealthCheck().getStats().get(key))
                        .collect(Collectors.joining(StringUtils.LF, StringUtils.EMPTY, StringUtils.EMPTY)));
                substitutes.put(LATEST_SERVICE_STATS, AgentInfo.getInstance().getJaHealthCheck().getServiceStatus().keySet().stream()
                        .map(key -> key + SEPARATOR + AgentInfo.getInstance().getJaHealthCheck().getServiceStatus().get(key))
                        .collect(Collectors.joining(StringUtils.LF, StringUtils.EMPTY, StringUtils.EMPTY)));
                substitutes.put(LAST_5_ERRORS, StringUtils.joinWith(StringUtils.LF, AgentUtils.getInstance().getStatusLogMostRecentErrors().toArray()));
                substitutes.put(LAST_5_HC, StringUtils.joinWith(StringUtils.LF, AgentUtils.getInstance().getStatusLogMostRecentHCs().toArray()));
                substitutes.put(VALIDATOR_SERVER_STATUS, AgentInfo.getInstance().getJaHealthCheck().getServiceStatus().getOrDefault(WEBSOCKET, StringUtils.EMPTY).toString());
                substitutes.put(ENFORCED_POLICY, JsonConverter.toJSON(AgentUtils.getInstance().getAgentPolicy()));
                StringSubstitutor substitutor = new StringSubstitutor(substitutes);
                FileUtils.writeStringToFile(statusLog, substitutor.replace(IAgentConstants.STATUS_FILE_TEMPLATE), StandardCharsets.UTF_8);
                isStatusLoggingActive = true;
            } else {
                isStatusLoggingActive = false;
                logger.log(LogLevel.SEVERE, CAN_T_CREATE_STATUS_LOG_FILE, HealthCheckScheduleThread.class.getName());
            }
        } catch (IOException e) {
            String error = String.format(CAN_T_WRITE_STATUS_LOG_FILE_S_REASON_S, statusLog, e.getMessage());
            isStatusLoggingActive = false;
            logger.log(LogLevel.SEVERE, error, e, HealthCheckScheduleThread.class.getName());
        }
    }

    private static Map<String, Object> getServiceStatus() {
        Map<String, Object> serviceStatus = new HashMap<>();
        /**
         * 1. websocket
         * 2. log writer
         * 3. agent active
         * 4. resource server
         * 5. IAST rest client
         * 6. Status log writer
         * */

        serviceStatus.put(WEBSOCKET, WSUtils.isConnected() ? "OK" : "Error");
        serviceStatus.put("logWriter", FileLoggerThreadPool.getInstance().isLoggingActive() ? "OK" : "Error");
        serviceStatus.put("initLogWriter", FileLoggerThreadPool.getInstance().isInitLoggingActive() ? "OK" : "Error");
        serviceStatus.put("statusLogWriter", isStatusLoggingActive ? "OK" : "Error");

        serviceStatus.put("agentActiveStat", AgentInfo.getInstance().isAgentActive() ? "OK" : "Error");

        serviceStatus.put("iastRestClient", RestClient.getInstance().isConnected() ? "OK" : "Error");

        return serviceStatus;
    }

    private static Map<String, Object> populateJVMStats() {

        Map<String, Object> stats = new HashMap<>();
        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();

        stats.put("processHeapUsageMB", NumberUtils.toScaledBigDecimal(memoryMXBean.getHeapMemoryUsage().getUsed() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("processMaxHeapMB", NumberUtils.toScaledBigDecimal(memoryMXBean.getHeapMemoryUsage().getMax() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("processRssMB", NumberUtils.toScaledBigDecimal((memoryMXBean.getHeapMemoryUsage().getUsed() + memoryMXBean.getNonHeapMemoryUsage().getUsed()) / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());

        stats.put("processFreeMemoryMB", NumberUtils.toScaledBigDecimal(Runtime.getRuntime().freeMemory() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        setOsStats(stats);
        stats.put("nCores", Runtime.getRuntime().availableProcessors());

        stats.put("rootDiskFreeSpaceMB", NumberUtils.toScaledBigDecimal(osVariables.getRootDir().getFreeSpace() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("processDirDiskFreeSpaceMB", NumberUtils.toScaledBigDecimal(new File(".").getFreeSpace() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());

        return stats;
    }

    private static void setOsStats(Map<String, Object> stats) {
        try {
            Object operatingSystemMXBean = ManagementFactory.getOperatingSystemMXBean();
            Method getProcessCpuLoad = operatingSystemMXBean.getClass().getMethod("getProcessCpuLoad");
            getProcessCpuLoad.setAccessible(true);
            Method getFreePhysicalMemorySize = operatingSystemMXBean.getClass().getMethod("getFreePhysicalMemorySize");
            getFreePhysicalMemorySize.setAccessible(true);
            Method getTotalPhysicalMemorySize = operatingSystemMXBean.getClass().getMethod("getTotalPhysicalMemorySize");
            getTotalPhysicalMemorySize.setAccessible(true);

            stats.put("systemCpuLoad", NumberUtils.toScaledBigDecimal(((OperatingSystemMXBean) operatingSystemMXBean).getSystemLoadAverage(), 2, RoundingMode.HALF_DOWN).doubleValue());
            stats.put("processCpuUsage", NumberUtils.toScaledBigDecimal((double) getProcessCpuLoad.invoke(operatingSystemMXBean), 2, RoundingMode.HALF_DOWN).doubleValue());

            stats.put("systemFreeMemoryMB", NumberUtils.toScaledBigDecimal(((long) getFreePhysicalMemorySize.invoke(operatingSystemMXBean)) / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
            stats.put("systemTotalMemoryMB", NumberUtils.toScaledBigDecimal(((long) getTotalPhysicalMemorySize.invoke(operatingSystemMXBean)) / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());

        } catch (Throwable e) {
//            logger.log(LogLevel.ERROR, "Error while populating OS related resource usage stats : " + e.toString(), HealthCheckScheduleThread.class.getName());
            logger.log(LogLevel.FINER, "Error while populating OS related resource usage stats : ", e, HealthCheckScheduleThread.class.getName());
        }
    }

    public static HealthCheckScheduleThread getInstance() {
        try {
            if (instance == null)
                instance = new HealthCheckScheduleThread();
            return instance;
        } catch (Throwable e) {
            logger.log(LogLevel.WARNING, "Error while starting: ", e, HealthCheckScheduleThread.class.getName());
        }
        throw null;
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
        instance = null;
    }

    /**
     * Shut down the thread pool executor. Calls normal shutdown of thread pool
     * executor and awaits for termination. If not terminated, forcefully shuts down
     * the executor after a timeout.
     */
    public void shutDownThreadPoolExecutor() {

        if (hcScheduledService != null) {
            try {
                hcScheduledService.shutdown(); // disable new tasks from being submitted
                if (!hcScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    hcScheduledService.shutdownNow(); // cancel currently executing tasks

                    if (!hcScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
                                HealthCheckScheduleThread.class.getName());
                    } else {
                        logger.log(LogLevel.INFO, "Thread pool executor terminated",
                                HealthCheckScheduleThread.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }
}