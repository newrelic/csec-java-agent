package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.javaagent.SQLOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Array;
import java.util.*;

public class ThreadLocalDBMap {

	private Map<Object, List<SQLOperationalBean>> sqlCalls;

	private static ThreadLocal<ThreadLocalDBMap> instance = new ThreadLocal<ThreadLocalDBMap>() {
		@Override protected ThreadLocalDBMap initialValue() {
			return new ThreadLocalDBMap();
		}
	};

	private ThreadLocalDBMap() {
		sqlCalls = new HashMap<>();
	}

	public static ThreadLocalDBMap getInstance() {
		return instance.get();
	}

	public void create(Object ref, String query) {
		SQLOperationalBean bean = new SQLOperationalBean();
		bean.setQuery(query);
		List<SQLOperationalBean> list;
		if (sqlCalls.containsKey(ref)) {
			list = sqlCalls.get(ref);
			list.add(bean);

		} else {
			list = new ArrayList<>();
			list.add(bean);
			sqlCalls.put(ref, list);

		}
	}

	public void setParam(Object ref, int position, Object value) {
		if (sqlCalls.containsKey(ref)) {
			List<SQLOperationalBean> beanList = sqlCalls.get(ref);

			if (value instanceof Array) {
				beanList.get(beanList.size() - 1).getParams().put(position, Arrays.asList(value).toString());
			} else if (value != null) {
				beanList.get(beanList.size() - 1).getParams().put(position, value.toString());
			}

		}
	}

	public void addBatch(Object ref, String query) {
		if(StringUtils.isNotBlank(query)) {
			create(ref, query);
		} else {
			if (sqlCalls.containsKey(ref)) {
				List<SQLOperationalBean> beanList = sqlCalls.get(ref);
				create(ref, beanList.get(beanList.size() - 1).getQuery());
			}
		}
	}

	public void clearBatch(Object ref) {
		if (sqlCalls.containsKey(ref)) {
			List<SQLOperationalBean> beanList = sqlCalls.get(ref);
			beanList.remove(beanList.size() - 1);
		}
	}
}
