package com.k2cybersecurity.instrumentator.decorators.mongo;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.NoSQLOperationalBean;

import java.time.Instant;

public class Callbacks {
    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && args != null
        ) {
            ThreadLocalOperationLock.getInstance().acquire();
            int streamingPayloadIndex = -1;
            try {
                switch (args.length) {
                    // For version 3.6.x - 3.12.x
                    case 9:
                        streamingPayloadIndex = 6;
                        break;
                    // For version 4.x and above
                    case 10:
                        streamingPayloadIndex = 7;
                        break;
                    default:
                }

                MongoPayload data = MongoPayload.getParser().generateMongoPayload(args, streamingPayloadIndex);

                if (data != null) {
                    EventDispatcher.dispatch(new NoSQLOperationalBean(data.getJSON(), className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.NOSQL_DB_COMMAND);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {

//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }
}
