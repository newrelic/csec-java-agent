package com.k2cybersecurity.instrumentator.custom;

import java.util.HashMap;
import java.util.Map;

public class ThreadLocalSessionMap {

    private Map<String, Object> sessionValues;

    /**
     * @return the sessionValues
     */
    public Map<String, Object> getSessionValues() {
        return sessionValues;
    }

    /**
     * @param sessionValues the sessionValues to set
     */
    public void setSessionValues(Map<String, Object> sessionValues) {
        this.sessionValues = sessionValues;
    }

    private static ThreadLocal<ThreadLocalSessionMap> instance = new ThreadLocal<ThreadLocalSessionMap>() {
        @Override
        protected ThreadLocalSessionMap initialValue() {
            return new ThreadLocalSessionMap();
        }
    };

    public boolean put(String key, Object value) {
        if (sessionValues.containsKey(key)) {
            return false;
        } else {
            sessionValues.put(key, value);
            return true;
        }
    }

    private ThreadLocalSessionMap() {
        sessionValues = new HashMap<>();
    }

    public static ThreadLocalSessionMap getInstance() {
        return instance.get();
    }

    public void clearAll() {
        sessionValues.clear();
    }

}
