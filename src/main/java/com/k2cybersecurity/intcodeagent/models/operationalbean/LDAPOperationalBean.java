package com.k2cybersecurity.intcodeagent.models.operationalbean;

public class LDAPOperationalBean extends AbstractOperationalBean {

	private String name;
	private String filter;
	
	public LDAPOperationalBean(String name, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.name = name;
	}
	
	public LDAPOperationalBean(String name, String filter, String className, String sourceMethod, String executionId, long startTime) {
		this(name, className, sourceMethod, executionId, startTime);
		this.filter = filter;
	}
	
	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the filter
	 */
	public String getFilter() {
		return filter;
	}

	/**
	 * @param filter the filter to set
	 */
	public void setFilter(String filter) {
		this.filter = filter;
	}

	@Override
	public boolean isEmpty() {
		return false;
	}

}
