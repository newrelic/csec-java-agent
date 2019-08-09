package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.net.URL;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.brutusin.instrumentation.Agent;

import com.google.gson.Gson;
import com.k2cybersecurity.intcodeagent.logging.LoggingInterceptor;

public class JAHealthCheck extends AgentBasicInfo{

	private static Logger logger;
	
	private String applicationUUID;

	private String protectedServer;

	private Set<String> protectedDB;

	private Boolean rceProtection;
	
	private Boolean ssrfProtection;

	private Set<String> instrumentedMethods;

	private AtomicInteger eventDropCount;

	private Set<String> jarPaths;
	
    private Boolean isHost;
    
    private AtomicInteger eventProcessed;
    
    private AtomicInteger eventSentCount;

	public JAHealthCheck(String applicationUUID) {
		super();
		this.rceProtection = false;
		this.ssrfProtection = false;
		this.applicationUUID = applicationUUID;
		this.setInstrumentedMethods(new HashSet<String>());
		this.setProtectedDB(new HashSet<String>());
		this.eventDropCount = new AtomicInteger(0);
		this.eventProcessed = new AtomicInteger(0);
		this.eventSentCount = new AtomicInteger(0);
		this.setIsHost(LoggingInterceptor.APPLICATION_INFO_BEAN.getIsHost());
		this.setJarPath();
		logger.log(Level.INFO,"JA Healthcheck created : {0}", this.toString());
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
		this.isHost = jaHealthCheck.isHost;
		this.setJarPath();
		logger.log(Level.INFO,"JA Healthcheck created : {0}", this.toString());
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
	}

	/**
	 * @return the protectedDB
	 */
	public Set<String> getProtectedDB() {
		return protectedDB;
	}

	/**
	 * @param protectedDB the protectedDB to set
	 */
	public void setProtectedDB(Set<String> protectedDB) {
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
	public Set<String> getInstrumentedMethods() {
		return instrumentedMethods;
	}

	/**
	 * @param instrumentedMethods the instrumentedMethods to set
	 */
	public void setInstrumentedMethods(Set<String> instrumentedMethods) {
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

	/**
	 * @return the jarPaths
	 */
	public Set<String> getJarPaths() {
		return jarPaths;
	}

	/**
	 * @param jarPaths the jarPaths to set
	 */
	public void setJarPaths(Set<String> jarPaths) {
		this.jarPaths = jarPaths;
	}

	public void setJarPath() {
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
					logger.log(Level.WARNING,"Exception in setJarPath : {0}", e1);
				} catch (Throwable e) {
					logger.log(Level.WARNING,"Throwable in setJarPath : {0}", e);
				}
			}
			if (Agent.jarPathSet.size() != lastJarSetSize) {
				this.setJarPaths(Agent.jarPathSet);
				Agent.allClassLoadersCount.set(Agent.allClassLoaders.size());
			}
		}
	}

	@Override
	public String toString() {
		return new Gson().toJson(this);
	}
	
	
	public static void setLogger() {
		JAHealthCheck.logger = Logger.getLogger(JAHealthCheck.class.getName());
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

}
