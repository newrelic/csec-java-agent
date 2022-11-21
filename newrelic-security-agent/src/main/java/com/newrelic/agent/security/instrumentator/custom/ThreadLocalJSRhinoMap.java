package com.newrelic.agent.security.instrumentator.custom;

import com.newrelic.agent.security.intcodeagent.models.operationalbean.JSInjectionOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ThreadLocalJSRhinoMap {

    private Map<Object, JSInjectionOperationalBean> jsInjectionCodeValues;

    private static ThreadLocal<ThreadLocalJSRhinoMap> instance = new ThreadLocal<ThreadLocalJSRhinoMap>() {
        @Override
        protected ThreadLocalJSRhinoMap initialValue() {
            return new ThreadLocalJSRhinoMap();
        }
    };

    private ThreadLocalJSRhinoMap() {
        jsInjectionCodeValues = new HashMap<>();
    }

    public static ThreadLocalJSRhinoMap getInstance() {
        return instance.get();
    }

    public void create(Object ref, String javaScriptCode, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        if (StringUtils.isBlank(javaScriptCode)) {
            return;
        }
        JSInjectionOperationalBean bean = new JSInjectionOperationalBean(javaScriptCode, className, sourceMethod, executionId, startTime, methodName);
        if (!jsInjectionCodeValues.containsKey(ref)) {
            jsInjectionCodeValues.put(ref, bean);
        }
    }

    public JSInjectionOperationalBean get(Object ref) {
        if (jsInjectionCodeValues.containsKey(ref)) {
            return jsInjectionCodeValues.get(ref);
        } else {
//			System.out.println("NOT FOUND");
        }
        return null;
    }

    public boolean clear(Object ref) {
        return jsInjectionCodeValues.remove(ref) != null;
    }

    public void clearAll() {
        jsInjectionCodeValues.clear();
    }

}
