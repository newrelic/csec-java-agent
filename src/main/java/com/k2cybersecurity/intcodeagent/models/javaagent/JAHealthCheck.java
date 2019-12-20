package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.instrumentation.Agent;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.LoggingInterceptor;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.json.simple.JSONArray;

import java.net.URL;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicInteger;

public class JAHealthCheck extends AgentBasicInfo{

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	
	private String applicationUUID;

	private String protectedServer;

	private JSONArray protectedDB;

	private Boolean rceProtection;
	
	private Boolean ssrfProtection;

	private JSONArray instrumentedMethods;

	private AtomicInteger eventDropCount;

    private Boolean isHost;
    
    private AtomicInteger eventProcessed;
    
    private AtomicInteger eventSentCount;



	private Boolean fileAccessProtection;

	public JAHealthCheck(String applicationUUID) {
		super();
		this.rceProtection = false;
		this.ssrfProtection = false;
		this.fileAccessProtection = false;
		this.applicationUUID = applicationUUID;
		this.eventDropCount = new AtomicInteger(0);
		this.eventProcessed = new AtomicInteger(0);
		this.eventSentCount = new AtomicInteger(0);
		this.setInstrumentedMethods(new JSONArray());
		this.setProtectedDB(new JSONArray());
		this.setIsHost(LoggingInterceptor.APPLICATION_INFO_BEAN.getIsHost());
		this.setLibPath();
		logger.log(LogLevel.INFO,"JA Healthcheck created : "+ this.toString(), JAHealthCheck.class.getName());
	}

	public JAHealthCheck(JAHealthCheck jaHealthCheck) {
		super();
		this.applicationUUID = jaHealthCheck.applicationUUID;
		this.protectedServer = jaHealthCheck.protectedServer;
		this.protectedDB = jaHealthCheck.protectedDB;
		this.rceProtection = jaHealthCheck.rceProtection;
		this.instrumentedMethods = jaHealthCheck.instrumentedMethods;
		this.eventDropCount = jaHealthCheck.eventDropCount;
		this.eventProcessed = jaHealthCheck.eventProcessed;
		this.eventSentCount = jaHealthCheck.eventSentCount;
		this.ssrfProtection = jaHealthCheck.ssrfProtection;
		this.fileAccessProtection = jaHealthCheck.fileAccessProtection;
		this.isHost = jaHealthCheck.isHost;
		this.setLibPath();
		logger.log(LogLevel.INFO,"JA Healthcheck created : "+ this.toString(), JAHealthCheck.class.getName());
	}

	/**
	 * @return the isHost
	 */
	public Boolean getIsHost() {
		return isHost;
	}

	/**
	 * @param isHost the isHost to set
	 */
	public void setIsHost(Boolean isHost) {
		this.isHost = isHost;
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
		LoggingInterceptor.APPLICATION_INFO_BEAN.getServerInfo().setName(protectedServer);
	}

	/**
	 * @return the protectedDB
	 */
	public JSONArray getProtectedDB() {
		return protectedDB;
	}

	/**
	 * @param protectedDB the protectedDB to set
	 */
	public void setProtectedDB(JSONArray protectedDB) {
		this.protectedDB = protectedDB;
	}

	/**
	 * @return the rceProtection
	 */
	public Boolean getRceProtection() {
		return rceProtection;
	}

	/**
	 * @param rceProtection the rceProtection to set
	 */
	public void setRceProtection(Boolean rceProtection) {
		this.rceProtection = rceProtection;
	}

	/**
	 * @return the instrumentedMethods
	 */
	public JSONArray getInstrumentedMethods() {
		return instrumentedMethods;
	}

	/**
	 * @param instrumentedMethods the instrumentedMethods to set
	 */
	public void setInstrumentedMethods(JSONArray instrumentedMethods) {
		this.instrumentedMethods = instrumentedMethods;
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

	public void setLibPath() {
		if (Agent.allClassLoaders.size() != Agent.allClassLoadersCount.get()) {
			int lastJarSetSize = Agent.jarPathSet.size();
			for (ClassLoader loader : Agent.allClassLoaders) {
				try {
					if (loader != null && loader instanceof ClassLoader) {
						Enumeration<URL> pathLisiting = loader.getResources("");
						while(pathLisiting.hasMoreElements()) {
							Agent.jarPathSet.add(pathLisiting.nextElement().getPath());
						}
					} 
				} catch (Exception e1) {
					logger.log(LogLevel.WARNING,"Exception in setLibPath : ", e1, JAHealthCheck.class.getName());
				} catch (Throwable e) {
					logger.log(LogLevel.WARNING,"Throwable in setLibPath : ", e, JAHealthCheck.class.getName());
				}
			}
			Agent.allClassLoadersCount.set(Agent.allClassLoaders.size());
			logger.log(LogLevel.DEBUG, "Current JarSet : " + Agent.jarPathSet,JAHealthCheck.class.getName());
//			if (Agent.jarPathSet.size() != lastJarSetSize) {
				JSONArray jarSet = new JSONArray();
				jarSet.addAll(Agent.jarPathSet);
			try {
				logger.log(LogLevel.INFO,"Waiting for 10 second to let application load all the files.", JAHealthCheck.class.getName());
				Thread.sleep(10*1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			LoggingInterceptor.updateServerInfo();
//			}
		}
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	/**
	 * @return the ssrfProtection
	 */
	public Boolean getSsrfProtection() {
		return ssrfProtection;
	}

	/**
	 * @param ssrfProtection the ssrfProtection to set
	 */
	public void setSsrfProtection(Boolean ssrfProtection) {
		this.ssrfProtection = ssrfProtection;
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

	public Boolean getFileAccessProtection() {
		return fileAccessProtection;
	}

	public void setFileAccessProtection(Boolean fileAccessProtection) {
		this.fileAccessProtection = fileAccessProtection;
	}
}
