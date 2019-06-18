package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JAHealthCheck  extends AgentBasicInfo implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 2569081419422389944L;
	
	private String applicationUUID;
	
	private String protectedServer;
	
	private Set<String> protectedDB;
	
	private Boolean rceProtection;
	
	private Set<String> instrumentedMethods;
	
	private Integer eventDropCount;
	
	public JAHealthCheck(String applicationUUID) {
		super();
		this.applicationUUID = applicationUUID;
		this.setInstrumentedMethods(new HashSet<String>());
		this.setProtectedDB(new HashSet<String>());
		this.eventDropCount = 0;
	}

	public JAHealthCheck(JAHealthCheck jaHealthCheck) {
		super();
		this.applicationUUID = jaHealthCheck.applicationUUID;
		this.protectedServer = jaHealthCheck.protectedServer;
		this.protectedDB = jaHealthCheck.protectedDB;
		this.rceProtection = jaHealthCheck.rceProtection;
		this.instrumentedMethods = jaHealthCheck.instrumentedMethods;
		this.eventDropCount = jaHealthCheck.eventDropCount;
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
		this.eventDropCount+=1;
	}
	
	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
	}

}
