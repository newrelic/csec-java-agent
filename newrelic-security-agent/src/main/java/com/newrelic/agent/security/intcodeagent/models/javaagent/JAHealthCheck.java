package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class JAHealthCheck extends AgentBasicInfo {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	private static final String HC_CREATED = "Created Health Check: %s";

    private long procStartTime;

    private long controlCommandRequestedTime;

    private long scanStartTime;

    private long trafficStartedTime;

    private final long csecActivationTime;

    private final long iastDataRequestTime;

    private Boolean scanActive = false;

    private final AtomicInteger invokedHookCount;

    private IdentifierEnvs kind;

    private final EventStats eventStats;

    private ThreadPoolStats threadPoolStats;

    private Map<String, Object> stats;

    private Map<String, Object> serviceStatus;

    private IastReplayRequest iastReplayRequest = new IastReplayRequest();

    private WebSocketConnectionStats webSocketConnectionStats = new WebSocketConnectionStats();

    private SchedulerRuns schedulerRuns = new SchedulerRuns();

    private String iastTestIdentifier;

    public JAHealthCheck() {
        super();
        this.invokedHookCount = new AtomicInteger(0);
        this.threadPoolStats = new ThreadPoolStats();
        this.stats = new HashMap<>();
        this.serviceStatus = new HashMap<>();
        this.eventStats = new EventStats();
        this.setKind(AgentInfo.getInstance().getApplicationInfo().getIdentifier().getKind());
        this.procStartTime = ManagementFactory.getRuntimeMXBean().getStartTime();
        this.iastTestIdentifier = AgentConfig.getInstance().getScanControllers().getIastTestIdentifier();
        if(AgentConfig.getInstance().getAgentMode().getScanSchedule().getNextScanTime() != null) {
            this.csecActivationTime = AgentConfig.getInstance().getAgentMode().getScanSchedule().getNextScanTime().getTime();
        } else {
            this.csecActivationTime = Instant.now().toEpochMilli();
        }
        if(AgentConfig.getInstance().getAgentMode().getScanSchedule().getDataCollectionTime() != null) {
            this.iastDataRequestTime = AgentConfig.getInstance().getAgentMode().getScanSchedule().getDataCollectionTime().getTime();
        } else {
            this.iastDataRequestTime = Instant.now().toEpochMilli();
        }
        logger.log(LogLevel.INFO, String.format(HC_CREATED, JsonConverter.toJSON(this)), JAHealthCheck.class.getName());
    }

    public JAHealthCheck(JAHealthCheck jaHealthCheck) {
        super();
        this.threadPoolStats = new ThreadPoolStats(jaHealthCheck.threadPoolStats);
        this.kind = jaHealthCheck.kind;
        this.stats = new HashMap<>(jaHealthCheck.stats);
        this.serviceStatus = new HashMap<>(jaHealthCheck.serviceStatus);
        this.eventStats = new EventStats(jaHealthCheck.eventStats);
        this.iastReplayRequest = new IastReplayRequest(jaHealthCheck.iastReplayRequest);
        this.schedulerRuns = new SchedulerRuns(jaHealthCheck.schedulerRuns);
        this.invokedHookCount = new AtomicInteger(jaHealthCheck.invokedHookCount.get());
        this.webSocketConnectionStats = new WebSocketConnectionStats(jaHealthCheck.webSocketConnectionStats);
        this.procStartTime = jaHealthCheck.getProcStartTime();
        this.controlCommandRequestedTime = jaHealthCheck.getControlCommandRequestedTime();
        this.scanStartTime = jaHealthCheck.getScanStartTime();
        this.trafficStartedTime = jaHealthCheck.getTrafficStartedTime();
        this.csecActivationTime = jaHealthCheck.getCsecActivationTime();
        this.iastDataRequestTime = jaHealthCheck.getIastDataRequestTime();
        this.scanActive = jaHealthCheck.getScanActive();
        this.iastTestIdentifier = jaHealthCheck.getIastTestIdentifier();
        logger.log(LogLevel.INFO, String.format(HC_CREATED, JsonConverter.toJSON(this)), JAHealthCheck.class.getName());
    }

    public IdentifierEnvs getKind() {
        return kind;
    }

    public void setKind(IdentifierEnvs kind) {
        this.kind = kind;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public Map<String, Object> getStats() {
        return stats;
    }

    public void setStats(Map<String, Object> stats) {
        this.stats = stats;
    }

    public Map<String, Object> getServiceStatus() {
        return serviceStatus;
    }

    public void setServiceStatus(Map<String, Object> serviceStatus) {
        this.serviceStatus = serviceStatus;
    }


    public ThreadPoolStats getThreadPoolStats() {
        return threadPoolStats;
    }

    public void setThreadPoolStats(ThreadPoolStats threadPoolStats) {
        this.threadPoolStats = threadPoolStats;
    }


    public int getInvokedHookCount() {
        return invokedHookCount.get();
    }

    public void setInvokedHookCount(int invokedHookCount) {
        this.invokedHookCount.set(invokedHookCount);
    }

    public int incrementInvokedHookCount() {
        return invokedHookCount.incrementAndGet();
    }

    public EventStats getEventStats() {
        return eventStats;
    }

    public IastReplayRequest getIastReplayRequest() {
        return iastReplayRequest;
    }

    public WebSocketConnectionStats getWebSocketConnectionStats() {
        return webSocketConnectionStats;
    }

    public SchedulerRuns getSchedulerRuns() {
        return schedulerRuns;
    }

    public void setSchedulerRuns(SchedulerRuns schedulerRuns) {
        this.schedulerRuns = schedulerRuns;
    }

    public long getProcStartTime() {
        return procStartTime;
    }

    public void setProcStartTime(long procStartTime) {
        this.procStartTime = procStartTime;
    }

    public long getControlCommandRequestedTime() {
        return controlCommandRequestedTime;
    }

    public void setControlCommandRequestedTime(long controlCommandRequestedTime) {
        this.controlCommandRequestedTime = controlCommandRequestedTime;
    }

    public long getScanStartTime() {
        return scanStartTime;
    }

    public void setScanStartTime(long scanStartTime) {
        this.scanStartTime = scanStartTime;
    }

    public long getTrafficStartedTime() {
        return trafficStartedTime;
    }

    public void setTrafficStartedTime(long trafficStartedTime) {
        this.trafficStartedTime = trafficStartedTime;
    }

    public long getCsecActivationTime() {
        return csecActivationTime;
    }

    public Boolean getScanActive() {
        return scanActive;
    }

    public void setScanActive(Boolean scanActive) {
        this.scanActive = scanActive;
    }

    public long getIastDataRequestTime() {
        return iastDataRequestTime;
    }

    public String getIastTestIdentifier() {
        return iastTestIdentifier;
    }

    public void setIastTestIdentifier(String iastTestIdentifier) {
        this.iastTestIdentifier = iastTestIdentifier;
    }

    public void reset(){
        this.setInvokedHookCount(0);
        this.stats.clear();
        this.serviceStatus.clear();
        this.eventStats.reset();
        this.iastReplayRequest.reset();
        this.webSocketConnectionStats.reset();
        this.schedulerRuns.reset();
    }
}
