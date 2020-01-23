package com.k2cybersecurity.instrumentator.custom;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.models.operationalbean.LDAPOperationalBean;

public class ThreadLocalLdaptiveMap {

	private Map<Object, LDAPOperationalBean> ldapFilterValues;
	
	private static ThreadLocal<ThreadLocalLdaptiveMap> instance = new ThreadLocal<ThreadLocalLdaptiveMap>() {
		@Override protected ThreadLocalLdaptiveMap initialValue() {
			return new ThreadLocalLdaptiveMap();
		}
	};

	private ThreadLocalLdaptiveMap() {
		ldapFilterValues = new HashMap<>();
	}

	public static ThreadLocalLdaptiveMap getInstance() {
		return instance.get();
	}

	public void create(Object ref, String filter, String className, String sourceMethod, String executionId, long startTime) {
		if (StringUtils.isBlank(filter)){
			return;
		}
		LDAPOperationalBean bean = new LDAPOperationalBean(className, sourceMethod, executionId, startTime);
		bean.setFilter(filter);
		bean.setClassName(className);
		bean.setSourceMethod(sourceMethod);
		bean.setExecutionId(executionId);
		bean.setStartTime(startTime);
		if (!ldapFilterValues.containsKey(ref)) {
			ldapFilterValues.put(ref, bean);
		}
	}

	public LDAPOperationalBean get(Object ref) {
		if (ldapFilterValues.containsKey(ref)) {
			return ldapFilterValues.get(ref);
		} else {
			System.out.println("NOT FOUND");
		}
		return null;
	}

	public boolean clear (Object ref) {
		return ldapFilterValues.remove(ref) != null ;
	}

	public void clearAll () {
		ldapFilterValues.clear();
	}
	
}
