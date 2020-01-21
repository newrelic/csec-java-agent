package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SQLOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Array;
import java.util.*;

public class ThreadLocalDBMap {

	public static final String UNKNOWN = "UNKNOWN";
	private Map<Object, List<SQLOperationalBean>> sqlCalls;
	
	private Set<SQLOperationalBean> sentSqlCalls;

	private static ThreadLocal<ThreadLocalDBMap> instance = new ThreadLocal<ThreadLocalDBMap>() {
		@Override protected ThreadLocalDBMap initialValue() {
			return new ThreadLocalDBMap();
		}
	};

	private ThreadLocalDBMap() {
		sqlCalls = new HashMap<>();
		sentSqlCalls = new HashSet<>();
	}

	public static ThreadLocalDBMap getInstance() {
		return instance.get();
	}

	public void setParam(Object ref, int position, Object value) {
		if (sqlCalls.containsKey(ref)) {
			List<SQLOperationalBean> beanList = sqlCalls.get(ref);

			if (value instanceof Array) {
				beanList.get(beanList.size() - 1).getParams().put(position, Arrays.asList(value).toString());
			} else if (value != null) {
				beanList.get(beanList.size() - 1).getParams().put(position, String.valueOf(value));
			}

		}
	}

	public void addBatch(Object ref, String query, String className, String sourceMethod, String executionId,
			long startTime, boolean isPreparedCall, Object thisRef, boolean needToGetConnection) {
		if (StringUtils.isNotBlank(query)) {
			create(ref, query, className, sourceMethod, executionId, startTime, true, isPreparedCall, thisRef, needToGetConnection);
		} else {
			if (sqlCalls.containsKey(ref)) {
				List<SQLOperationalBean> beanList = sqlCalls.get(ref);
				create(ref, beanList.get(beanList.size() - 1).getQuery(), className, sourceMethod, executionId, startTime, true,
						isPreparedCall,thisRef, needToGetConnection);
			}
		}
	}

	public void create(Object ref, String query, String className, String sourceMethod, String executionId, long startTime, boolean isBatch,
			boolean isPreparedCall, Object thisRef, boolean needToGetConnection) {
		if (StringUtils.isBlank(query)){
			return;
		}
		
		String dbName = UNKNOWN;
		if(thisRef != null) {
			//Get connection information
			dbName = CallbackUtils.getConnectionInformation(ref, needToGetConnection);
		}
		
		SQLOperationalBean bean = new SQLOperationalBean();
		bean.setQuery(query);
		bean.setClassName(className);
		bean.setSourceMethod(sourceMethod);
		bean.setExecutionId(executionId);
		bean.setStartTime(startTime);
		bean.setPreparedCall(isPreparedCall);
		bean.setDbName(dbName);
		List<SQLOperationalBean> list;
		if (sqlCalls.containsKey(ref) && isBatch) {
			list = sqlCalls.get(ref);
			list.add(bean);

		} else if(!sqlCalls.containsKey(ref) && !isBatch) {
			list = new ArrayList<>();
			list.add(bean);
			sqlCalls.put(ref, list);
		}
	}

	public void clearBatch(Object ref) {
		if (sqlCalls.containsKey(ref)) {
			List<SQLOperationalBean> beanList = sqlCalls.get(ref);
			beanList.remove(beanList.size() - 1);
		}
	}

	public List<SQLOperationalBean> get(Object ref) {
		if (sqlCalls.containsKey(ref)) {
			return sqlCalls.get(ref);
		}
		return null;
	}

	public boolean clear (Object ref) {
		return sqlCalls.remove(ref) != null ;
	}

	public void clearAll () {
		sentSqlCalls.clear();
		sqlCalls.clear();
	}

	public SQLOperationalBean checkAndUpdateSentSQLCalls(SQLOperationalBean bean) {
		if(sentSqlCalls.contains(bean)){
			return null;
		} else {
			sentSqlCalls.add(bean);
			return bean;
		}
	}
}
