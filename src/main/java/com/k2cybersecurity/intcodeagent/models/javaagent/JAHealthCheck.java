package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class JAHealthCheck extends AgentBasicInfo {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String applicationUUID;

	private String protectedServer;

	private Set protectedDB;

	private AtomicInteger eventDropCount;

    private IdentifierEnvs kind;

    private AtomicInteger eventProcessed;

    private AtomicInteger eventSentCount;

    private AtomicInteger httpRequestCount;

    private Set protectedVulnerabilities;

    public JAHealthCheck(String applicationUUID) {
        super();
        this.applicationUUID = applicationUUID;
        this.setProtectedServer(K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getName());
        this.eventDropCount = new AtomicInteger(0);
        this.eventProcessed = new AtomicInteger(0);
        this.eventSentCount = new AtomicInteger(0);
        this.httpRequestCount = new AtomicInteger(0);
        this.setProtectedDB(new HashSet());
        this.setProtectedVulnerabilities(AgentUtils.getInstance().getProtectedVulnerabilties());
        this.setKind(K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind());
        logger.log(LogLevel.INFO, "JA Healthcheck created : " + this.toString(), JAHealthCheck.class.getName());
    }

	public JAHealthCheck(JAHealthCheck jaHealthCheck) {
        super();
        this.applicationUUID = jaHealthCheck.applicationUUID;
        this.protectedServer = jaHealthCheck.protectedServer;
        this.protectedDB = jaHealthCheck.protectedDB;
        this.protectedVulnerabilities = jaHealthCheck.protectedVulnerabilities;
        this.eventDropCount = jaHealthCheck.eventDropCount;
        this.eventProcessed = jaHealthCheck.eventProcessed;
        this.eventSentCount = jaHealthCheck.eventSentCount;
        this.httpRequestCount = jaHealthCheck.httpRequestCount;
        this.kind = jaHealthCheck.kind;
        logger.log(LogLevel.INFO, "JA Healthcheck created : " + this.toString(), JAHealthCheck.class.getName());
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
	 * @return the protectedServer
	 */
	public String getProtectedServer() {
		return protectedServer;
	}

	/**
	 * @param protectedServer the protectedServer to set
	 */
	public void setProtectedServer(String protectedServer) {
		this.protectedServer = protectedServer;
		K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().setName(protectedServer);
	}

	/**
	 * @return the protectedDB
	 */
	public Set getProtectedDB() {
		return protectedDB;
	}

	/**
	 * @param protectedDB the protectedDB to set
	 */
	public void setProtectedDB(Set protectedDB) {
		this.protectedDB = protectedDB;
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
	
	public void incrementProcessedCount() {
		this.eventProcessed.getAndIncrement();
	}

	public void incrementEventSentCount() {
		this.eventSentCount.getAndIncrement();
	}

	public void decrementEventSentCount() {
		this.eventSentCount.getAndDecrement();
	}

	public void incrementHttpRequestCount() {
		this.httpRequestCount.getAndIncrement();
	}

	public void decrementHttpRequestCount() {
		this.httpRequestCount.getAndDecrement();
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

    public Set getProtectedVulnerabilities() {
        return protectedVulnerabilities;
    }

    public void setProtectedVulnerabilities(Set protectedVulnerabilities) {
        this.protectedVulnerabilities = protectedVulnerabilities;
    }

    public void setHttpRequestCount(Integer httpRequestCount) {
        this.httpRequestCount.set(httpRequestCount);
    }
}
