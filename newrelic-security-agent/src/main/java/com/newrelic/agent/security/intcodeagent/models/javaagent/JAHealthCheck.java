package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class JAHealthCheck extends AgentBasicInfo {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	private static final String HC_CREATED = "Created Health Check: %s";

    private String applicationUUID;

//    private String protectedServer;

//    private Set protectedDB;

    private AtomicInteger invokedHookCount;

    private AtomicInteger eventDropCount;

    private AtomicInteger eventRejectionCount;

    private AtomicInteger eventProcessingErrorCount;

    private AtomicInteger eventSendRejectionCount;

    private AtomicInteger eventSendErrorCount;

    private IdentifierEnvs kind;

    private AtomicInteger eventProcessed;

    private AtomicInteger eventSentCount;

    private AtomicInteger exitEventSentCount;

    private AtomicInteger httpRequestCount;

    private EventStats raspEventStats;

    private EventStats iastEventStats;

    private EventStats exitEventStats;

    private ThreadPoolStats threadPoolStats;

    private Map<String, Object> stats;

    private Map<String, Object> serviceStatus;

//    private Set protectedVulnerabilities;

    private Integer dsBackLog;

    public JAHealthCheck(String applicationUUID) {
        super();
        this.applicationUUID = applicationUUID;
        this.invokedHookCount = new AtomicInteger(0);
        this.eventDropCount = new AtomicInteger(0);
        this.eventProcessed = new AtomicInteger(0);
        this.eventSentCount = new AtomicInteger(0);
        this.httpRequestCount = new AtomicInteger(0);
        this.exitEventSentCount = new AtomicInteger(0);
        this.eventRejectionCount = new AtomicInteger(0);
        this.eventProcessingErrorCount = new AtomicInteger(0);
        this.eventSendRejectionCount = new AtomicInteger(0);
        this.eventSendErrorCount = new AtomicInteger(0);
        this.raspEventStats = new EventStats();
        this.iastEventStats = new EventStats();
        this.exitEventStats = new EventStats();
        this.threadPoolStats = new ThreadPoolStats();
        this.stats = new HashMap<>();
        this.serviceStatus = new HashMap<>();
        this.setKind(AgentInfo.getInstance().getApplicationInfo().getIdentifier().getKind());
        logger.log(LogLevel.INFO, String.format(HC_CREATED, JsonConverter.toJSON(this)), JAHealthCheck.class.getName());
    }

    public JAHealthCheck(JAHealthCheck jaHealthCheck) {
        super();
        this.applicationUUID = jaHealthCheck.applicationUUID;
        this.invokedHookCount =  new AtomicInteger(jaHealthCheck.invokedHookCount.intValue());
        this.eventDropCount =  new AtomicInteger(jaHealthCheck.eventDropCount.intValue());
        this.eventProcessed =  new AtomicInteger(jaHealthCheck.eventProcessed.intValue());
        this.eventSentCount =  new AtomicInteger(jaHealthCheck.eventSentCount.intValue());
        this.exitEventSentCount =  new AtomicInteger(jaHealthCheck.exitEventSentCount.intValue());
        this.httpRequestCount =  new AtomicInteger(jaHealthCheck.httpRequestCount.intValue());
        this.eventRejectionCount =  new AtomicInteger(jaHealthCheck.eventRejectionCount.intValue());
        this.eventProcessingErrorCount =  new AtomicInteger(jaHealthCheck.eventProcessingErrorCount.intValue());
        this.eventSendRejectionCount =  new AtomicInteger(jaHealthCheck.eventSendRejectionCount.intValue());
        this.eventSendErrorCount =  new AtomicInteger(jaHealthCheck.eventSendErrorCount.intValue());
        this.raspEventStats = new EventStats(jaHealthCheck.raspEventStats);
        this.iastEventStats = new EventStats(jaHealthCheck.iastEventStats);
        this.exitEventStats = new EventStats(jaHealthCheck.exitEventStats);
        this.threadPoolStats = new ThreadPoolStats(jaHealthCheck.threadPoolStats);
        this.kind = jaHealthCheck.kind;
        this.stats = new HashMap<>(jaHealthCheck.stats);
        this.serviceStatus = new HashMap<>(jaHealthCheck.serviceStatus);
        this.dsBackLog = jaHealthCheck.dsBackLog;
        logger.log(LogLevel.INFO, String.format(HC_CREATED, JsonConverter.toJSON(this)), JAHealthCheck.class.getName());
    }

    public IdentifierEnvs getKind() {
        return kind;
    }

    public void setKind(IdentifierEnvs kind) {
        this.kind = kind;
    }

    /**
     * @return the applicationUUID
     */
    public String getApplicationUUID() {
        return applicationUUID;
    }

    /**
     * @param applicationUUID the applicationUUID to set
     */
    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    /**
     * @return the eventDropCount
     */
    public Integer getEventDropCount() {
        return eventDropCount.get();
    }

    /**
     * @param eventDropCount the eventDropCount to set
     */
    public void setEventDropCount(Integer eventDropCount) {
        this.eventDropCount.set(eventDropCount);
    }

    public void incrementDropCount() {
        this.eventDropCount.getAndIncrement();
    }

    public AtomicInteger getEventRejectionCount() {
        return eventRejectionCount;
    }

    public void setEventRejectionCount(int eventRejectionCount) {
        this.eventRejectionCount.set(eventRejectionCount);
    }

    public int incrementEventRejectionCount(){
        return eventRejectionCount.incrementAndGet();
    }

    public AtomicInteger getEventProcessingErrorCount() {
        return eventProcessingErrorCount;
    }

    public void setEventProcessingErrorCount(int eventProcessingErrorCount) {
        this.eventProcessingErrorCount.set(eventProcessingErrorCount);
    }

    public int incrementEventProcessingErrorCount() {
        return eventProcessingErrorCount.incrementAndGet();
    }

    public AtomicInteger getEventSendRejectionCount() {
        return eventSendRejectionCount;
    }

    public void setEventSendRejectionCount(int eventSendRejectionCount) {
        this.eventSendRejectionCount.set(eventSendRejectionCount);
    }

    public int incrementEventSendRejectionCount() {
        return this.eventSendRejectionCount.incrementAndGet();
    }

    public AtomicInteger getEventSendErrorCount() {
        return eventSendErrorCount;
    }

    public void setEventSendErrorCount(int eventSendErrorCount) {
        this.eventSendErrorCount.set(eventSendErrorCount);
    }

    public int incrementEventSendErrorCount() {
        return this.eventSendErrorCount.incrementAndGet();
    }

    public void incrementProcessedCount() {
        this.eventProcessed.getAndIncrement();
    }

    public void incrementEventSentCount() {
        this.eventSentCount.getAndIncrement();
    }

    public void decrementEventSentCount() {
        this.eventSentCount.getAndDecrement();
    }

    public AtomicInteger getExitEventSentCount() {
        return exitEventSentCount;
    }

    public AtomicInteger getHttpRequestCount() {
        return httpRequestCount;
    }

    public void incrementHttpRequestCount() {
        this.httpRequestCount.getAndIncrement();
    }

    public void decrementHttpRequestCount() {
        this.httpRequestCount.getAndDecrement();
    }

    public void incrementExitEventSentCount() {
        this.exitEventSentCount.getAndIncrement();
    }

    public void decrementExitEventSentCount() {
        this.exitEventSentCount.getAndDecrement();
    }

    public void setExitEventSentCount(Integer exitEventSentCount) {
        this.exitEventSentCount.set(exitEventSentCount);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    /**
     * @return the eventProcessed
     */
    public Integer getEventProcessed() {
        return eventProcessed.get();
    }

    /**
     * @param eventProcessed the eventProcessed to set
     */
    public void setEventProcessed(Integer eventProcessed) {
        this.eventProcessed.set(eventProcessed);
    }

    /**
     * @return the eventSentCount
     */
    public AtomicInteger getEventSentCount() {
        return eventSentCount;
    }

    /**
     * @param eventSentCount the eventSentCount to set
     */
    public void setEventSentCount(Integer eventSentCount) {
        this.eventSentCount.set(eventSentCount);
    }

    public void setHttpRequestCount(Integer httpRequestCount) {
        this.httpRequestCount.set(httpRequestCount);
    }

    public Integer getDsBackLog() {
        return dsBackLog;
    }

    public void setDsBackLog(Integer dsBackLog) {
        this.dsBackLog = dsBackLog;
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

    public EventStats getRaspEventStats() {
        return raspEventStats;
    }

    public void setRaspEventStats(EventStats raspEventStats) {
        this.raspEventStats = raspEventStats;
    }

    public EventStats getIastEventStats() {
        return iastEventStats;
    }

    public void setIastEventStats(EventStats iastEventStats) {
        this.iastEventStats = iastEventStats;
    }

    public ThreadPoolStats getThreadPoolStats() {
        return threadPoolStats;
    }

    public void setThreadPoolStats(ThreadPoolStats threadPoolStats) {
        this.threadPoolStats = threadPoolStats;
    }

    public EventStats getExitEventStats() {
        return exitEventStats;
    }

    public void setExitEventStats(EventStats exitEventStats) {
        this.exitEventStats = exitEventStats;
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

    public void reset(){
        this.setEventDropCount(0);
        this.setInvokedHookCount(0);
        this.setEventProcessed(0);
        this.setEventSentCount(0);
        this.setHttpRequestCount(0);
        this.setExitEventSentCount(0);
        this.setEventRejectionCount(0);
        this.setEventProcessingErrorCount(0);
        this.setEventSendRejectionCount(0);
        this.setEventSendErrorCount(0);
        this.raspEventStats.reset();
        this.iastEventStats.reset();
        this.exitEventStats.reset();
        this.stats.clear();
        this.serviceStatus.clear();
    }
}
