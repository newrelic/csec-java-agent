package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class SQLOperationalBean {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String query;

	private Map<Integer, String> params;

	private String className;

	public SQLOperationalBean() {
		this.query = StringUtils.EMPTY;
		this.params = new HashMap<>();
		this.className = StringUtils.EMPTY;
	}

	public SQLOperationalBean(SQLOperationalBean sqlOperationalBean) {
		this.query = sqlOperationalBean.getQuery();
		this.params = new HashMap<>(sqlOperationalBean.getParams());
		this.className = sqlOperationalBean.className;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public String getQuery() {
		return query;
	}

	public void setQuery(String query) {
		this.query = query;
	}

	public Map<Integer, String> getParams() {
		return params;
	}

	public void setParams(Map<Integer, String> params) {
		this.params = params;
	}

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}
}
