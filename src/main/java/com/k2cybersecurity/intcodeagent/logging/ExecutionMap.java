package com.k2cybersecurity.intcodeagent.logging;

import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ExecutionMap {

	private Integer executionId;
	
	private ServletInfo servletInfo;

	/**
	 * @param executionId
	 * @param servletInfo
	 */
	public ExecutionMap(Integer executionId, ServletInfo servletInfo) {
		super();
		this.executionId = executionId;
		this.servletInfo = servletInfo;
	}
	
	public ExecutionMap() {
	}
	
	public ExecutionMap(Integer executionId) {
		super();
		this.executionId = executionId;
	}

	/**
	 * @return the executionId
	 */
	public Integer getExecutionId() {
		return executionId;
	}

	/**
	 * @param executionId the executionId to set
	 */
	public void setExecutionId(Integer executionId) {
		this.executionId = executionId;
	}

	/**
	 * @return the servletInfo
	 */
	public ServletInfo getServletInfo() {
		return servletInfo;
	}

	/**
	 * @param servletInfo the servletInfo to set
	 */
	public void setServletInfo(ServletInfo servletInfo) {
		this.servletInfo = servletInfo;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((executionId == null) ? 0 : executionId.hashCode());
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof ExecutionMap))
			return false;
		ExecutionMap other = (ExecutionMap) obj;
		if (executionId == null) {
			if (other.executionId != null)
				return false;
		} else if (!executionId.equals(other.executionId))
			return false;
		return true;
	}
	
	
	public static ServletInfo find(Integer executionId, ConcurrentLinkedDeque<ExecutionMap> executionMaps) {
		Iterator<ExecutionMap> iterator = executionMaps.descendingIterator();
		while(iterator.hasNext()) {
			ExecutionMap executionMap = iterator.next();
			if(executionMap.getExecutionId() <= executionId)
				return executionMap.getServletInfo();
		}
		return null;
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
