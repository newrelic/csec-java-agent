package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class SQLOperationalBean extends AbstractOperationalBean{

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String query;

	private Map<Integer, String> params;

	public SQLOperationalBean() {
		super();
		this.query = StringUtils.EMPTY;
		this.params = new HashMap<>();
	}

	public SQLOperationalBean(SQLOperationalBean sqlOperationalBean) {
		super(sqlOperationalBean);
		this.query = sqlOperationalBean.getQuery();
		this.params = new HashMap<>(sqlOperationalBean.getParams());
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

}

