package com.k2cybersecurity.instrumentator.decorators.forkexec;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.ForkExecOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {

		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - eid : " + exectionId);

				String command = StringUtils.join((String[]) args[0], StringUtils.SPACE);
				if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && ((String[]) args[0]).length != 0) {
					if (StringUtils.isNotBlank(command)) {
						ForkExecOperationalBean forkExecOperationalBean = new ForkExecOperationalBean(command,
								(Map<String, String>) args[1], className, sourceString, exectionId,
								Instant.now().toEpochMilli());
						EventDispatcher.dispatch(forkExecOperationalBean, VulnerabilityCaseType.SYSTEM_COMMAND);
					}
				} else if (StringUtils.isNotBlank(command)) {
					ForkExecOperationalBean forkExecOperationalBean = new ForkExecOperationalBean(command,
							(Map<String, String>) args[1], className, sourceString, exectionId,
							Instant.now().toEpochMilli());
					EventDispatcher.dispatch(forkExecOperationalBean, VulnerabilityCaseType.SYSTEM_COMMAND, true);
				}

			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - return : " + returnVal + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {

		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}

	}
}
