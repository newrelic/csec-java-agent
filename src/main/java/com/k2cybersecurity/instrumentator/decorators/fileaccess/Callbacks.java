package com.k2cybersecurity.instrumentator.decorators.fileaccess;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.time.Instant;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
		if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && StringUtils.isNotBlank(args[0].toString())) {
			FileOperationalBean fileOperationalBean = new FileOperationalBean(args[0].toString(), className,
					sourceString, exectionId, Instant.now().toEpochMilli());
			ThreadLocalExecutionMap.getInstance().getFileLocalMap().put(args[0].toString(),
					new FileIntegrityBean(new File(args[0].toString()).exists(), args[0].toString(), className,
							sourceString, exectionId, Instant.now().toEpochMilli()));
			EventDispatcher.dispatch(fileOperationalBean, VulnerabilityCaseType.FILE_OPERATION);
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
				+ " - error : " + error + " - eid : " + exectionId);
	}
}
