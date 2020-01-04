package com.k2cybersecurity.instrumentator.decorators.ldap;

import java.time.Instant;
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.LDAPOperationalBean;

public class Callbacks {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String executionId) {
		logger.log(LogLevel.INFO, "OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
				+ " - eid : " + executionId, Callbacks.class.getName());
		if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args.length != 0) {
			
			String name = args[0].toString();
			if (StringUtils.isNotBlank(name)) {
				LDAPOperationalBean ldapOperationalBean = new LDAPOperationalBean(name, className, sourceString,
						executionId, Instant.now().toEpochMilli());
				String filter = args[1].toString();
				if (StringUtils.isNotBlank(filter)) {
					ldapOperationalBean.setFilter(filter);
				}
				EventDispatcher.dispatch(ldapOperationalBean, VulnerabilityCaseType.LDAP);
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
				+ " - return : " + returnVal + " - eid : " + exectionId);
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
				+ " - error : " + error + " - eid : " + exectionId);
	}
}
