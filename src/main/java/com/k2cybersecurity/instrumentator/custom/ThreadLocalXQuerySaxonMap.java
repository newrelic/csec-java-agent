package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.operationalbean.XQueryOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ThreadLocalXQuerySaxonMap {

    private Map<Object, XQueryOperationalBean> xqueryExpressionValues;

    private boolean compileStartMarked = false;

    private String tempBuffer = null;

    private static ThreadLocal<ThreadLocalXQuerySaxonMap> instance = new ThreadLocal<ThreadLocalXQuerySaxonMap>() {
        @Override
        protected ThreadLocalXQuerySaxonMap initialValue() {
            return new ThreadLocalXQuerySaxonMap();
        }
    };

    private ThreadLocalXQuerySaxonMap() {
        xqueryExpressionValues = new HashMap<>();
    }

    public static ThreadLocalXQuerySaxonMap getInstance() {
        return instance.get();
    }

    public void create(Object ref, String expression, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        if (StringUtils.isBlank(expression)) {
            return;
        }
        XQueryOperationalBean bean = new XQueryOperationalBean(expression, className, sourceMethod, executionId, startTime, methodName);
        if (!xqueryExpressionValues.containsKey(ref)) {
            xqueryExpressionValues.put(ref, bean);
        }
    }

    public XQueryOperationalBean get(Object ref) {
        if (xqueryExpressionValues.containsKey(ref)) {
            return xqueryExpressionValues.get(ref);
        } else {
//			System.out.println("NOT FOUND");
        }
        return null;
    }

    public boolean clear(Object ref) {
        return xqueryExpressionValues.remove(ref) != null;
    }

    public void clearAll() {
        xqueryExpressionValues.clear();
    }

    public boolean isCompileStartMarked() {
        return compileStartMarked;
    }

    public void setCompileStartMarked(boolean compileStartMarked) {
        this.compileStartMarked = compileStartMarked;
    }

    public String getTempBuffer() {
        return tempBuffer;
    }

    public void setTempBuffer(String tempBuffer) {
        this.tempBuffer = tempBuffer;
    }

}
