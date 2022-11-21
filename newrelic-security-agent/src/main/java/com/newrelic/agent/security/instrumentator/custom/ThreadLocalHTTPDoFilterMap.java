package com.newrelic.agent.security.instrumentator.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public class ThreadLocalHTTPDoFilterMap {

    @JsonIgnore
    private Class<?> currentGenericServletInstance;

    @JsonIgnore
    private String currentGenericServletMethodName = StringUtils.EMPTY;

    @JsonIgnore
    private int currentGenericServletStackLength = -1;

    @JsonIgnore
    private boolean userCodeEncountered = false;

    public boolean isUserCodeEncountered() {
        return userCodeEncountered;
    }

    public void setUserCodeEncountered(boolean userCodeEncountered) {
        this.userCodeEncountered = userCodeEncountered;
    }

    public Class<?> getCurrentGenericServletInstance() {
        return currentGenericServletInstance;
    }

    public void setCurrentGenericServletInstance(Class<?> currentGenericServletInstance) {
        this.currentGenericServletInstance = currentGenericServletInstance;
    }

    public String getCurrentGenericServletMethodName() {
        return currentGenericServletMethodName;
    }

    public void setCurrentGenericServletMethodName(String currentGenericServletMethodName) {
        this.currentGenericServletMethodName = currentGenericServletMethodName;
    }

    public int getCurrentGenericServletStackLength() {
        return currentGenericServletStackLength;
    }

    public void setCurrentGenericServletStackLength(int currentGenericServletStackLength) {
        this.currentGenericServletStackLength = currentGenericServletStackLength;
    }

    private static ThreadLocal<ThreadLocalHTTPDoFilterMap> instance =
            new ThreadLocal<ThreadLocalHTTPDoFilterMap>() {
                @Override
                protected ThreadLocalHTTPDoFilterMap initialValue() {
                    return new ThreadLocalHTTPDoFilterMap();
                }
            };

    private ThreadLocalHTTPDoFilterMap() {
    }

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
        userCodeEncountered = false;
        currentGenericServletStackLength = -1;
    }

}
