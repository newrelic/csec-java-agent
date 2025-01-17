package com.newrelic.agent.security.intcodeagent.logging;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.apache.httpclient.IastHttpClient;
import com.newrelic.agent.security.intcodeagent.apache.httpclient.SecurityClient;
import com.newrelic.agent.security.intcodeagent.communication.ConnectionFactory;
import com.newrelic.agent.security.intcodeagent.controlcommand.ControlCommandProcessorThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ThreadPoolActiveStat;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JAHealthCheck;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ThreadPoolStats;
import com.newrelic.agent.security.intcodeagent.schedulers.SchedulerHelper;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
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
import com.sun.management.OperatingSystemMXBean;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class HealthCheckScheduleThread {

    public static final String WEBSOCKET = "websocket";
    private static HealthCheckScheduleThread instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private ScheduledFuture future;

    private static boolean isStatusLoggingActive = true;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private Runnable runnable = new Runnable() {
        public void run() {
            JAHealthCheck sendJaHealthCheck = null;
            try {
                // since tcp connection keep alive check is more than 2 hours
                // we send our custom object to check if connection is still alive or not
                // this will be ignored by ic agent on the other side.

                AgentInfo.getInstance().getJaHealthCheck().setStats(populateJVMStats());
                AgentInfo.getInstance().getJaHealthCheck().setServiceStatus(getServiceStatus());
                AgentInfo.getInstance().getJaHealthCheck().setThreadPoolStats(populateThreadPoolStats());

                if (!AgentInfo.getInstance().isAgentActive()) {
                    return;
                }

                logger.log(LogLevel.INFO, String.format("Pending CCs to be processed : %s", RestRequestThreadPool.getInstance().getQueueSize()), this.getClass().getName());
                AgentInfo.getInstance().getJaHealthCheck().getIastReplayRequest().incrementPendingControlCommandsBy(RestRequestThreadPool.getInstance().getQueueSize());
                AgentInfo.getInstance().getJaHealthCheck().getIastReplayRequest().incrementPendingControlCommandsBy(GrpcClientRequestReplayHelper.getInstance().getRequestQueue().size());
                AgentUtils.getInstance().addStatusLogMostRecentHCs(AgentInfo.getInstance().getJaHealthCheck().toString());
//						channel.write(ByteBuffer.wrap(new JAHealthCheck(AgentNew.JA_HEALTH_CHECK).toString().getBytes()));
                if (ConnectionFactory.getInstance().getSecurityConnection().isConnected()) {
                    synchronized (AgentInfo.getInstance().getJaHealthCheck()){
                        sendJaHealthCheck = new JAHealthCheck(AgentInfo.getInstance().getJaHealthCheck());
                        AgentInfo.getInstance().getJaHealthCheck().reset();
                    }
                    ConnectionFactory.getInstance().getSecurityConnection().send(sendJaHealthCheck, "postAny");
                }

            } catch (NullPointerException ex) {
                logger.log(LogLevel.WARNING, "No reference to Socket's OutputStream",
                        HealthCheckScheduleThread.class.getName());
            } catch (Throwable e) {
                logger.log(LogLevel.WARNING, "Error while trying to verify connection: ", e,
                        HealthCheckScheduleThread.class.getName());
            }
        }
    };

    private ThreadPoolStats populateThreadPoolStats() {
        ThreadPoolStats threadPoolStats = new ThreadPoolStats();
        threadPoolStats.setDispatcher(new ThreadPoolActiveStat(DispatcherPool.getInstance().getExecutor().getActiveCount(),
                DispatcherPool.getInstance().getExecutor().getQueue().size()));
        threadPoolStats.setEventSender(new ThreadPoolActiveStat(EventSendPool.getInstance().getExecutor().getActiveCount(),
                EventSendPool.getInstance().getExecutor().getQueue().size()));
        threadPoolStats.setControlCommandProcessor(new ThreadPoolActiveStat(ControlCommandProcessorThreadPool.getInstance().getExecutor().getActiveCount(),
                ControlCommandProcessorThreadPool.getInstance().getExecutor().getQueue().size()));
        threadPoolStats.setIastHttpRequestProcessor(new ThreadPoolActiveStat(RestRequestThreadPool.getInstance().getExecutor().getActiveCount(),
                RestRequestThreadPool.getInstance().getExecutor().getQueue().size()));
        threadPoolStats.setFileLogger(new ThreadPoolActiveStat(FileLoggerThreadPool.getInstance().getExecutor().getActiveCount(),
                FileLoggerThreadPool.getInstance().getExecutor().getQueue().size()));

        return threadPoolStats;
    }

    private HealthCheckScheduleThread() {}

    public void scheduleNewTask() {
        future = SchedulerHelper.getInstance().scheduleHealthCheck(runnable, 30, 300, TimeUnit.SECONDS);
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

        serviceStatus.put("iastRestClient", IastHttpClient.getInstance().isConnected() ? "OK" : "Error");

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
            OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

            stats.put("systemCpuLoad", NumberUtils.toScaledBigDecimal(osBean.getSystemLoadAverage(), 2, RoundingMode.HALF_DOWN).doubleValue());
            stats.put("processCpuUsage", NumberUtils.toScaledBigDecimal(osBean.getProcessCpuLoad()*100, 2, RoundingMode.HALF_DOWN).doubleValue());

            stats.put("systemFreeMemoryMB", NumberUtils.toScaledBigDecimal(osBean.getFreePhysicalMemorySize() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
            stats.put("systemTotalMemoryMB", NumberUtils.toScaledBigDecimal(osBean.getTotalPhysicalMemorySize() / 1048576.0, 2, RoundingMode.HALF_DOWN).doubleValue());
        } catch (Throwable e) {
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
}