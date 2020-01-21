package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class SQLOperationalBean extends AbstractOperationalBean{

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private String query;

	private Map<Integer, String> params;
	
	private String dbName;

	private boolean isPreparedCall;

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

	public boolean isPreparedCall() {
		return isPreparedCall;
	}

	public void setPreparedCall(boolean preparedCall) {
		isPreparedCall = preparedCall;
	}

	@Override public boolean isEmpty() {
		if(StringUtils.isBlank(query)){
			return true;
		} else if(isPreparedCall) {
			if(StringUtils.contains(query, "?") && params.isEmpty()){
				return true;
			}
		}
		return false;
	}

	@Override public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		SQLOperationalBean that = (SQLOperationalBean) o;
		return query.equals(that.query) && params.equals(that.params);
	}

	@Override public int hashCode() {
		return Objects.hash(query, params);
	}

	/**
	 * @return the dbName
	 */
	public String getDbName() {
		return dbName;
	}

	/**
	 * @param dbName the dbName to set
	 */
	public void setDbName(String dbName) {
		this.dbName = dbName;
	}
}

