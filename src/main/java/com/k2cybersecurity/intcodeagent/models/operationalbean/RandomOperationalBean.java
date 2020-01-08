package com.k2cybersecurity.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

public class RandomOperationalBean extends AbstractOperationalBean {

	private String eventCatgory;
	
	public RandomOperationalBean(String eventCatgory, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.eventCatgory = eventCatgory;
	}

	/**
	 * @return the eventCatgory
	 */
	public String getEventCatgory() {
		return eventCatgory;
	}

	/**
	 * @param eventCatgory the eventCatgory to set
	 */
	public void setEventCatgory(String eventCatgory) {
		this.eventCatgory = eventCatgory;
	}

	@Override
	public boolean isEmpty() {
		// TODO Auto-generated method stub
		return StringUtils.isBlank(eventCatgory);
	}

	
}
