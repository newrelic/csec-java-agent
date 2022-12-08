package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

public class RandomOperation extends AbstractOperation {

    private String eventCatgory;

    public RandomOperation(String eventCatgory, String className, String methodName) {
        super(className, methodName);
        this.eventCatgory = eventCatgory;
    }

    /**
     * @return the eventCatgory
     */
    public String getEventCatgory() {
        return eventCatgory;
    }

    /**
     * @param eventCatgory the eventCatgory to set
     */
    public void setEventCatgory(String eventCatgory) {
        this.eventCatgory = eventCatgory;
    }

    @Override
    public boolean isEmpty() {
        // TODO Auto-generated method stub
        return (eventCatgory == null || eventCatgory.trim().isEmpty());
    }


}
