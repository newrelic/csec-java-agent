package org.brutusin.instrumentation.logging;

import org.brutusin.com.fasterxml.jackson.core.JsonProcessingException;
import org.brutusin.com.fasterxml.jackson.databind.ObjectMapper;

import com.k2.org.json.simple.JSONArray;

public class ApplicationInfoBean {

	private Integer pid;
	private String applicatioNname;
	private JSONArray jvmArguments;
	private Long startTime;
	
	public ApplicationInfoBean() {}
	
	public ApplicationInfoBean(Integer pid) {
		this.pid = pid;
		this.startTime = System.currentTimeMillis();
	}
	/**
	 * @return the pid
	 */
	public Integer getPid() {
		return pid;
	}
	/**
	 * @param pid the pid to set
	 */
	public void setPid(Integer pid) {
		this.pid = pid;
	}
	/**
	 * @return the applicatioNname
	 */
	public String getApplicatioNname() {
		return applicatioNname;
	}
	/**
	 * @param applicatioNname the applicatioNname to set
	 */
	public void setApplicatioNname(String applicatioNname) {
		this.applicatioNname = applicatioNname;
	}
	/**
	 * @return the jvmArguments
	 */
	public JSONArray getJvmArguments() {
		return jvmArguments;
	}
	/**
	 * @param jvmArguments the jvmArguments to set
	 */
	public void setJvmArguments(JSONArray jvmArguments) {
		this.jvmArguments = jvmArguments;
	}
	
	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
	}
	/**
	 * @return the startTime
	 */
	public Long getStartTime() {
		return startTime;
	}
	/**
	 * @param startTime the startTime to set
	 */
	public void setStartTime(Long startTime) {
		this.startTime = startTime;
	}
	
}
