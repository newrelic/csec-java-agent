package com.newrelic.agent.security.intcodeagent.logging;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.httpclient.RestClient;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
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
                AgentInfo.getInstance().getJaHealthCheck().getIastReplayRequest().incrementReplayRequestExecutedBy(GrpcClientRequestReplayHelper.getInstance().getReplayRequestExecuted());
                AgentInfo.getInstance().getJaHealthCheck().getIastReplayRequest().incrementReplayRequestFailedBy(GrpcClientRequestReplayHelper.getInstance().getReplayRequestFailed());
                AgentInfo.getInstance().getJaHealthCheck().getIastReplayRequest().incrementReplayRequestSucceededBy(GrpcClientRequestReplayHelper.getInstance().getReplayRequestSucceeded());
                GrpcClientRequestReplayHelper.getInstance().resetReplayRequestMetric();
                AgentUtils.getInstance().addStatusLogMostRecentHCs(AgentInfo.getInstance().getJaHealthCheck().toString());
//						channel.write(ByteBuffer.wrap(new JAHealthCheck(AgentNew.JA_HEALTH_CHECK).toString().getBytes()));
                if (WSClient.getInstance().isOpen()) {
                    synchronized (AgentInfo.getInstance().getJaHealthCheck()){
                        sendJaHealthCheck = new JAHealthCheck(AgentInfo.getInstance().getJaHealthCheck());
                        AgentInfo.getInstance().getJaHealthCheck().reset();
                    }
                    WSClient.getInstance().send(JsonConverter.toJSON(sendJaHealthCheck));
                }

            } catch (NullPointerException ex) {
                logger.log(LogLevel.WARNING, "No reference to Socket's OutputStream",
                        HealthCheckScheduleThread.class.getName());
            } catch (Throwable e) {
                logger.log(LogLevel.WARNING, "Error while trying to verify connection: ", e,
                        HealthCheckScheduleThread.class.getName());
            } finally {
                writeStatusLogFile(sendJaHealthCheck);
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
        future = SchedulerHelper.getInstance().scheduleHealthCheck(runnable, 300, 300, TimeUnit.SECONDS);
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

    private void writeStatusLogFile(JAHealthCheck sendJaHealthCheck) {
        JAHealthCheck writerHealthCheck = sendJaHealthCheck;
        if(writerHealthCheck == null){
            writerHealthCheck = AgentInfo.getInstance().getJaHealthCheck();
        }
        File statusLog = new File(osVariables.getSnapshotDir(), String.format(K_2_AGENT_STATUS_LOG, AgentInfo.getInstance().getApplicationUUID()));
        try {
            FileUtils.deleteQuietly(statusLog);
            if (statusLog.createNewFile()) {
                Map<String, String> substitutes = AgentUtils.getInstance().getStatusLogValues();
                substitutes.put(STATUS_TIMESTAMP, Instant.now().toString());
                JAHealthCheck finalWriterHealthCheck = writerHealthCheck;
                substitutes.put(LATEST_PROCESS_STATS, finalWriterHealthCheck.getStats().keySet().stream()
                        .map(key -> key + SEPARATOR + finalWriterHealthCheck.getStats().get(key))
                        .collect(Collectors.joining(StringUtils.LF, StringUtils.EMPTY, StringUtils.EMPTY)));
                substitutes.put(LATEST_SERVICE_STATS, finalWriterHealthCheck.getServiceStatus().keySet().stream()
                        .map(key -> key + SEPARATOR + finalWriterHealthCheck.getServiceStatus().get(key))
                        .collect(Collectors.joining(StringUtils.LF, StringUtils.EMPTY, StringUtils.EMPTY)));
                substitutes.put(LAST_5_ERRORS, StringUtils.joinWith(StringUtils.LF, AgentUtils.getInstance().getStatusLogMostRecentErrors().toArray()));
                substitutes.put(LAST_5_HC, StringUtils.joinWith(StringUtils.LF, AgentUtils.getInstance().getStatusLogMostRecentHCs().toArray()));
                substitutes.put(VALIDATOR_SERVER_STATUS, finalWriterHealthCheck.getServiceStatus().getOrDefault(WEBSOCKET, StringUtils.EMPTY).toString());
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