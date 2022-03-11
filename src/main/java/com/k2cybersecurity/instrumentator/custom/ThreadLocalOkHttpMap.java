package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ThreadLocalOkHttpMap {

    private Map<Object, SSRFOperationalBean> operationalBeanMap;

    private static ThreadLocal<ThreadLocalOkHttpMap> instance = new ThreadLocal<ThreadLocalOkHttpMap>() {
        @Override
        protected ThreadLocalOkHttpMap initialValue() {
            return new ThreadLocalOkHttpMap();
        }
    };

    private ThreadLocalOkHttpMap() {
        operationalBeanMap = new HashMap<>();
    }

    public static ThreadLocalOkHttpMap getInstance() {
        return instance.get();
    }

    public SSRFOperationalBean create(Object ref, String args, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        if (StringUtils.isBlank(args)) {
            return null;
        }
        SSRFOperationalBean bean = new SSRFOperationalBean(args, className, sourceMethod, executionId, startTime, methodName);
        if (!operationalBeanMap.containsKey(ref)) {
            operationalBeanMap.put(ref, bean);
        }
        return bean;
    }

    public SSRFOperationalBean get(Object ref) {
        if (operationalBeanMap.containsKey(ref)) {
            return operationalBeanMap.get(ref);
        } else {
//			System.out.println("NOT FOUND");
        }
        return null;
    }

    public boolean clear(Object ref) {
        return operationalBeanMap.remove(ref) != null;
    }

    public void clearAll() {
        operationalBeanMap.clear();
    }

}
