package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.brutusin.instrumentation.Agent;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.intcodeagent.logging.LoggingInterceptor;

public class JAHealthCheck extends AgentBasicInfo implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2569081419422389944L;
	
	private static Logger logger;
	
	private String applicationUUID;

	private String protectedServer;

	private Set<String> protectedDB;

	private Boolean rceProtection;

	private Set<String> instrumentedMethods;

	private Integer eventDropCount;

	private Set<String> jarPaths;
	
    private Boolean isHost;

	public JAHealthCheck(String applicationUUID) {
		super();
		this.rceProtection = false;
		this.applicationUUID = applicationUUID;
		this.setInstrumentedMethods(new HashSet<String>());
		this.setProtectedDB(new HashSet<String>());
		this.eventDropCount = 0;
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
	 * @return the serialversionuid
	 */
	public static long getSerialversionuid() {
		return serialVersionUID;
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
		return eventDropCount;
	}

	/**
	 * @param eventDropCount the eventDropCount to set
	 */
	public void setEventDropCount(Integer eventDropCount) {
		this.eventDropCount = eventDropCount;
	}

	public void incrementDropCount() {
		this.eventDropCount += 1;
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
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
	}
	
	
	public static void setLogger() {
		JAHealthCheck.logger = Logger.getLogger(JAHealthCheck.class.getName());
	}

}
