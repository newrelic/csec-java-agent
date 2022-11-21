package com.newrelic.agent.security.instrumentator.decorators.jndi;



import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.FileOperationalBean;
import com.newrelic.agent.security.intcodeagent.models.operationalbean.SSRFOperationalBean;
import com.newrelic.agent.security.instrumentator.custom.*;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {
        if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalJNDILock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null && args.length == 1) {

                    ThreadLocalJNDILock.getInstance().acquire(obj, sourceString, exectionId);
                    List<String> references = new ArrayList<>();

                    if (args[0] instanceof String) {
                        references.add((String) args[0]);
                    } else {
                        try {
                            Method getAll = args[0].getClass().getMethod("getAll");
                            getAll.setAccessible(true);
                            Enumeration<String> allNames = (Enumeration<String>) getAll.invoke(args[0]);
                            while (allNames.hasMoreElements()) {
                                references.add(allNames.nextElement());
                            }
                        } catch (Exception e) {
                        }
                    }

                    for (String reference : references) {
                        try {
                            URI url = new URI(reference);
//                            if (StringUtils.equals("file", url.getScheme()) || StringUtils.isBlank(url.getScheme())) {
//                                // TODO : Research required to ensure that a file access attack is possible via JNDI.
////                                handleFileAccess(url.getPath(), className, sourceString, exectionId, methodName);
//                            } else {
//                                handleSSRF(reference, className, sourceString, exectionId, methodName);
//                            }

                            if (StringUtils.isNotBlank(url.getScheme()) && (
                                    StringUtils.equalsIgnoreCase(url.getScheme(), "ldap")
                                            || StringUtils.equalsIgnoreCase(url.getScheme(), "rmi")
                                            || StringUtils.equalsIgnoreCase(url.getScheme(), "dns")
                                            || StringUtils.equalsIgnoreCase(url.getScheme(), "iiop")
                            )) {
                                handleSSRF(reference, className, sourceString, exectionId, methodName);
                            }
                        } catch (Exception e) {
//                            handleFileAccess(reference, className, sourceString, exectionId, methodName);
                        }
                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void placeAdditionalTemplateData() {
        if (ThreadLocalJNDILock.getInstance().getBuf() == null) {
            return;
        }
        String baseData = StringUtils.substring(ThreadLocalJNDILock.getInstance().getBuf().toString(),
                ThreadLocalJNDILock.getInstance().getStartPos(),
                ThreadLocalJNDILock.getInstance().getEndPos());

        if (StringUtils.isNoneBlank(ThreadLocalJNDILock.getInstance().getMappingValue(),
                baseData)
                && StringUtils.equals(ThreadLocalJNDILock.getInstance().getMappingValue().trim(), baseData.trim())) {
            return;
        }

        ThreadLocalExecutionMap.getInstance().getMetaData().getUserDataTranslationMap().put(
                ThreadLocalJNDILock.getInstance().getMappingValue(), baseData);
    }

    private static void handleFileAccess(String reference, String className, String sourceString, String exectionId,
                                         String methodName) throws K2CyberSecurityException {
        placeAdditionalTemplateData();
        EventDispatcher.dispatch(new FileOperationalBean(new File(reference).getAbsolutePath(), className,
                        sourceString, exectionId, Instant.now().toEpochMilli(), false, methodName),
                VulnerabilityCaseType.FILE_OPERATION);

    }

    private static void handleSSRF(String reference, String className, String sourceString, String exectionId,
                                   String methodName) throws K2CyberSecurityException {
        placeAdditionalTemplateData();
        EventDispatcher.dispatch(new SSRFOperationalBean(reference, className, sourceString, exectionId,
                Instant.now().toEpochMilli(), methodName, true), VulnerabilityCaseType.HTTP_REQUEST);
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalJNDILock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            ThreadLocalJNDILock.getInstance().release(obj, sourceString, exectionId);
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
                    EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.HTTP_REQUEST);
                }
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalJNDILock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                ThreadLocalJNDILock.getInstance().release(obj, sourceString, exectionId);
            } finally {
                DispatcherPool.getInstance().getEid().remove(exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }

    }
}
