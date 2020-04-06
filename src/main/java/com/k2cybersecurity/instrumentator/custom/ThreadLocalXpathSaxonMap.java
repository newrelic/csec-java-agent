package com.k2cybersecurity.instrumentator.custom;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.models.operationalbean.XPathOperationalBean;

public class ThreadLocalXpathSaxonMap {

	private Map<Object, XPathOperationalBean> xpathExpressionValues;
	
	private static ThreadLocal<ThreadLocalXpathSaxonMap> instance = new ThreadLocal<ThreadLocalXpathSaxonMap>() {
		@Override protected ThreadLocalXpathSaxonMap initialValue() {
			return new ThreadLocalXpathSaxonMap();
		}
	};

	private ThreadLocalXpathSaxonMap() {
		xpathExpressionValues = new HashMap<>();
	}

	public static ThreadLocalXpathSaxonMap getInstance() {
		return instance.get();
	}

	public void create(Object ref, String expression, String className, String sourceMethod, String executionId, long startTime) {
		if (StringUtils.isBlank(expression)){
			return;
		}
		XPathOperationalBean bean = new XPathOperationalBean(expression, className, sourceMethod, executionId, startTime);
		if (!xpathExpressionValues.containsKey(ref)) {
			xpathExpressionValues.put(ref, bean);
		}
	}

	public XPathOperationalBean get(Object ref) {
		if (xpathExpressionValues.containsKey(ref)) {
			return xpathExpressionValues.get(ref);
		} else {
//			System.out.println("NOT FOUND");
		}
		return null;
	}

	public boolean clear (Object ref) {
		return xpathExpressionValues.remove(ref) != null ;
	}

	public void clearAll () {
		xpathExpressionValues.clear();
	}
	
}
