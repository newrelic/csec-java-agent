package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.RestClient;
import com.k2cybersecurity.instrumentator.httpclient.RestRequestThreadPool;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpConnectionStat;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.schedulers.InBoundOutBoundST;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
import com.sun.management.OperatingSystemMXBean;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.text.StringSubstitutor;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HCSCHEDULEDTHREAD_;

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
    public static final String PERMISSIONS = "rwxrwxrwx";
    private static HealthCheckScheduleThread instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static ScheduledExecutorService hcScheduledService;

    private static boolean isStatusLoggingActive = true;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private HealthCheckScheduleThread() {
        Runnable runnable = new Runnable() {
            public void run() {

                try {
                    // since tcp connection keep alive check is more than 2 hours
                    // we send our custom object to check if connection is still alive or not
                    // this will be ignored by ic agent on the other side.

                    if (!AgentUtils.getInstance().isAgentActive()) {
                        return;
                    }

                    K2Instrumentator.JA_HEALTH_CHECK.setStat(populateJVMStats());
                    K2Instrumentator.JA_HEALTH_CHECK.setServiceStatus(getServiceStatus());

                    K2Instrumentator.JA_HEALTH_CHECK.setDsBackLog(RestRequestThreadPool.getInstance().getQueueSize());
                    AgentUtils.getInstance().getStatusLogMostRecentHCs().add(K2Instrumentator.JA_HEALTH_CHECK.toString());
//						channel.write(ByteBuffer.wrap(new JAHealthCheck(AgentNew.JA_HEALTH_CHECK).toString().getBytes()));
                    if (WSClient.getInstance().isOpen()) {
                        InBoundOutBoundST.getInstance().task(InBoundOutBoundST.getInstance().getNewConnections(), false);
                        WSClient.getInstance().send(new JAHealthCheck(K2Instrumentator.JA_HEALTH_CHECK).toString());
                        K2Instrumentator.JA_HEALTH_CHECK.setEventDropCount(0);
                        K2Instrumentator.JA_HEALTH_CHECK.setEventProcessed(0);
                        K2Instrumentator.JA_HEALTH_CHECK.setEventSentCount(0);
                        K2Instrumentator.JA_HEALTH_CHECK.setHttpRequestCount(0);
                        K2Instrumentator.JA_HEALTH_CHECK.setExitEventSentCount(0);
                    }

                } catch (NullPointerException ex) {
                    logger.log(LogLevel.WARN, "No reference to Socket's OutputStream",
                            HealthCheckScheduleThread.class.getName());
                } catch (Throwable e) {
                    logger.log(LogLevel.WARN, "Error while trying to verify connection: ", e,
                            HealthCheckScheduleThread.class.getName());
                } finally {
                    InBoundOutBoundST.getInstance().clearNewConnections();
                    writeStatusLogFile();
                }
            }
        };
        hcScheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        HCSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
            }
        });
        hcScheduledService.scheduleAtFixedRate(runnable, 1, 5, TimeUnit.MINUTES);
        HttpConnectionStat httpConnectionStat = new HttpConnectionStat(Collections.emptyList(), K2Instrumentator.APPLICATION_UUID, false);
        InBoundOutBoundST.getInstance().clearNewConnections();
        createSnapshotDirectory();
    }

    private void createSnapshotDirectory() {
        Path snapshotDir = Paths.get(osVariables.getSnapshotDir());
        if (snapshotDir.toFile().isDirectory()) {
            FileUtils.deleteQuietly(snapshotDir.toFile());
        }
        CommonUtils.forceMkdirs(snapshotDir, PERMISSIONS);
    }

    private void writeStatusLogFile() {
        File statusLog = new File(osVariables.getSnapshotDir(), String.format(K_2_AGENT_STATUS_LOG, K2Instrumentator.APPLICATION_UUID));
        try {
            FileUtils.deleteQuietly(statusLog);
            if (statusLog.createNewFile()) {
                Map<String, String> substitutes = AgentUtils.getInstance().getStatusLogValues();
                substitutes.put(STATUS_TIMESTAMP, Instant.now().toString());
                substitutes.put(LATEST_PROCESS_STATS, K2Instrumentator.JA_HEALTH_CHECK.getStat().toString());
                substitutes.put(LATEST_SERVICE_STATS, K2Instrumentator.JA_HEALTH_CHECK.getServiceStatus().toString());
                substitutes.put(LAST_5_ERRORS, StringUtils.joinWith(StringUtils.LF, AgentUtils.getInstance().getStatusLogMostRecentErrors().toArray()));
                substitutes.put(LAST_5_HC, StringUtils.joinWith(StringUtils.LF, AgentUtils.getInstance().getStatusLogMostRecentHCs().toArray()));
                substitutes.put(VALIDATOR_SERVER_STATUS, K2Instrumentator.JA_HEALTH_CHECK.getServiceStatus().getOrDefault(WEBSOCKET, StringUtils.EMPTY).toString());
                substitutes.put(ENFORCED_POLICY, AgentUtils.getInstance().getAgentPolicy().toString());
                StringSubstitutor substitutor = new StringSubstitutor(substitutes);
                FileUtils.writeStringToFile(statusLog, substitutor.replace(IAgentConstants.STATUS_FILE_TEMPLATE), StandardCharsets.UTF_8);
                isStatusLoggingActive = true;
            }
        } catch (IOException e) {
            String error = String.format(CAN_T_WRITE_STATUS_LOG_FILE_S_REASON_S, statusLog, e.getMessage());
            isStatusLoggingActive = false;
            logger.log(LogLevel.ERROR, error, e, HealthCheckScheduleThread.class.getName());
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

        serviceStatus.put(WEBSOCKET, WSClient.isConnected() ? "OK" : "Error");
        serviceStatus.put("logWriter", FileLoggerThreadPool.getInstance().isLoggingActive() ? "OK" : "Error");
        serviceStatus.put("initLogWriter", FileLoggerThreadPool.getInstance().isInitLoggingActive() ? "OK" : "Error");
        serviceStatus.put("statusLogWriter", isStatusLoggingActive ? "OK" : "Error");

        serviceStatus.put("agentActiveStat", AgentUtils.getInstance().isAgentActive() ? "OK" : "Error");

        serviceStatus.put("resourceServer", HttpClient.getInstance().isConnected() ? "OK" : "Error");
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

        OperatingSystemMXBean operatingSystemMXBean = (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

        stats.put("systemCpuLoad", NumberUtils.toScaledBigDecimal(operatingSystemMXBean.getSystemLoadAverage(), 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("processCpuUsage", NumberUtils.toScaledBigDecimal(operatingSystemMXBean.getProcessCpuLoad(), 2, RoundingMode.HALF_DOWN).doubleValue());

        stats.put("systemFreeMemoryMB", NumberUtils.toScaledBigDecimal(operatingSystemMXBean.getFreePhysicalMemorySize() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("systemTotalMemoryMB", NumberUtils.toScaledBigDecimal(operatingSystemMXBean.getTotalPhysicalMemorySize() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("nCores", Runtime.getRuntime().availableProcessors());

        stats.put("rootDiskFreeSpaceMB", NumberUtils.toScaledBigDecimal(osVariables.getRootDir().getFreeSpace() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        stats.put("processDirDiskFreeSpaceMB", NumberUtils.toScaledBigDecimal(new File(".").getFreeSpace() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());

        return stats;
    }

    public static HealthCheckScheduleThread getInstance() {
        try {
            if (instance == null)
                instance = new HealthCheckScheduleThread();
            return instance;
        } catch (Throwable e) {
            logger.log(LogLevel.WARN, "Error while starting: ", e, HealthCheckScheduleThread.class.getName());
        }
        throw null;
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

        if (hcScheduledService != null) {
            try {
                hcScheduledService.shutdown(); // disable new tasks from being submitted
                if (!hcScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    hcScheduledService.shutdownNow(); // cancel currently executing tasks

                    if (!hcScheduledService.awaitTermination(1, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.FATAL, "Thread pool executor did not terminate",
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