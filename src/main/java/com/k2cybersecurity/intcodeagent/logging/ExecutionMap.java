package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedDeque;

public class ExecutionMap {

	private Long executionId;
	
	private HttpRequestBean servletInfo;

	private AgentMetaData metaData;
	
	/**
	 * @param executionId
	 * @param servletInfo
	 */
	public ExecutionMap(Long executionId, HttpRequestBean servletInfo) {
		super();
		this.executionId = executionId;
		this.servletInfo = servletInfo;
		this.metaData = new AgentMetaData();
	}
	
	public ExecutionMap(Long executionId) {
		super();
		this.executionId = executionId;
	}

	/**
	 * @return the executionId
	 */
	public Long getExecutionId() {
		return executionId;
	}

	/**
	 * @param executionId the executionId to set
	 */
	public void setExecutionId(Long executionId) {
		this.executionId = executionId;
	}

	/**
	 * @return the servletInfo
	 */
	public HttpRequestBean getServletInfo() {
		return servletInfo;
	}

	/**
	 * @param servletInfo the servletInfo to set
	 */
	public void setServletInfo(HttpRequestBean servletInfo) {
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
	
	
	public static Pair<HttpRequestBean, AgentMetaData> find(Long executionId, ConcurrentLinkedDeque<ExecutionMap> executionMaps) {
		Iterator<ExecutionMap> iterator = executionMaps.descendingIterator();
		while(iterator.hasNext()) {
			ExecutionMap executionMap = iterator.next();
			if(executionMap.getExecutionId() <= executionId)
				return new ImmutablePair<>(executionMap.getServletInfo(), executionMap.getMetaData());
		}
		return null;
	}

	@Override
	public String toString() {
			return JsonConverter.toJSON(this);
	}

	public AgentMetaData getMetaData() {
		return metaData;
	}

	public void setMetaData(AgentMetaData metaData) {
		this.metaData = metaData;
	}
}
