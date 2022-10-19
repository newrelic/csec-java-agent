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
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
import com.sun.management.OperatingSystemMXBean;
import org.apache.commons.lang3.math.NumberUtils;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.math.RoundingMode;
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

    private static HealthCheckScheduleThread instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static ScheduledExecutorService hcScheduledService;

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
        hcScheduledService.scheduleAtFixedRate(runnable, 5, 5, TimeUnit.MINUTES);
        HttpConnectionStat httpConnectionStat = new HttpConnectionStat(Collections.emptyList(), K2Instrumentator.APPLICATION_UUID, false);
        InBoundOutBoundST.getInstance().clearNewConnections();
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

        serviceStatus.put("websocket", WSClient.isConnected() ? "OK" : "Error");
        serviceStatus.put("log-writer", FileLoggerThreadPool.getInstance().isLoggingActive() ? "OK" : "Error");
        serviceStatus.put("status-log-writer", FileLoggerThreadPool.getInstance().isStatusLoggingActive() ? "OK" : "Error");

        serviceStatus.put("agent-active-stat", AgentUtils.getInstance().isAgentActive() ? "OK" : "Error");

        serviceStatus.put("resource-server", HttpClient.getInstance().isConnected() ? "OK" : "Error");
        serviceStatus.put("iast-rest-client", RestClient.getInstance().isConnected() ? "OK" : "Error");

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