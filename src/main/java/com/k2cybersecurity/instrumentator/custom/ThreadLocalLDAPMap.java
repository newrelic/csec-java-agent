package com.k2cybersecurity.instrumentator.custom;

import java.util.HashSet;
import java.util.Set;

public class ThreadLocalLDAPMap {

	private Set<String> ldapQueryValues;

	/**
	 * @return the ldapQueryValues
	 */
	public Set<String> getLdapQueryValues() {
		return ldapQueryValues;
	}

	/**
	 * @param ldapQueryValues the ldapQueryValues to set
	 */
	public void setLdapQueryValues(Set<String> ldapQueryValues) {
		this.ldapQueryValues = ldapQueryValues;
	}

	private static ThreadLocal<ThreadLocalLDAPMap> instance = new ThreadLocal<ThreadLocalLDAPMap>() {
		@Override protected ThreadLocalLDAPMap initialValue() {
			return new ThreadLocalLDAPMap();
		}
	};
	
	public boolean put(String key) {
		if(ldapQueryValues.contains(key)) {
			return false;
		}else {
			ldapQueryValues.add(key);
			return true;
		}
	}

	private ThreadLocalLDAPMap() {
		ldapQueryValues = new HashSet<>();
	}

	public static ThreadLocalLDAPMap getInstance() {
		return instance.get();
	}

	public void clearAll () {
		ldapQueryValues.clear();
	}

}
