package com.k2cybersecurity.instrumentator.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ThreadLocalHTTPDoFilterMap {

    @JsonIgnore
    private Object currentGenericServletInstance;

    @JsonIgnore
    private String currentGenericServletMethodName = StringUtils.EMPTY;


    public Object getCurrentGenericServletInstance() {
        return currentGenericServletInstance;
    }

    public void setCurrentGenericServletInstance(Object currentGenericServletInstance) {
        this.currentGenericServletInstance = currentGenericServletInstance;
    }

    public String getCurrentGenericServletMethodName() {
        return currentGenericServletMethodName;
    }

    public void setCurrentGenericServletMethodName(String currentGenericServletMethodName) {
        this.currentGenericServletMethodName = currentGenericServletMethodName;
    }

    private static ThreadLocal<ThreadLocalHTTPDoFilterMap> instance =
            new ThreadLocal<ThreadLocalHTTPDoFilterMap>() {
                @Override
                protected ThreadLocalHTTPDoFilterMap initialValue() {
                    return new ThreadLocalHTTPDoFilterMap();
                }
            };

    private ThreadLocalHTTPDoFilterMap() {}

    public static ThreadLocalHTTPDoFilterMap getInstance() {
        return instance.get();
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

	public void cleanUp() {
		currentGenericServletInstance = null;
		currentGenericServletMethodName = StringUtils.EMPTY;
	}

}
