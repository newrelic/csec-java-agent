package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.intcodeagent.models.javaagent.ServletInfo;

public class ThreadRequestData extends ExecutionMap {

	private Long launcherThreadId;
	
	/**
	 * @param executionId
	 * @param threadId
	 * @param servletInfo
	 */
	public ThreadRequestData(Long executionId, ServletInfo servletInfo, long threadId) {
		super(executionId, servletInfo);
		this.launcherThreadId = threadId;
	}

	/**
	 * @return the launcherThreadId
	 */
	public Long getLauncherThreadId() {
		return launcherThreadId;
	}

	/**
	 * @param launcherThreadId the launcherThreadId to set
	 */
	public void setLauncherThreadId(Long launcherThreadId) {
		this.launcherThreadId = launcherThreadId;
	}

}
