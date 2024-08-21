package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class DroppedEvents {

    private AtomicInteger unsupportedContentType = new AtomicInteger();

    private AtomicInteger nrInternalEvent = new AtomicInteger();

    private AtomicInteger csecInternalEvent = new AtomicInteger();

    private AtomicInteger executorUnavailable = new AtomicInteger();

    private AtomicInteger raspProcessingDeactivated = new AtomicInteger();

    private AtomicInteger rxssDetectionDeactivated = new AtomicInteger();

    public DroppedEvents() {
    }

    public DroppedEvents(DroppedEvents droppedEvents) {
        this.unsupportedContentType.set(droppedEvents.unsupportedContentType.get());
        this.nrInternalEvent.set(droppedEvents.nrInternalEvent.get());
        this.csecInternalEvent.set(droppedEvents.csecInternalEvent.get());
        this.executorUnavailable.set(droppedEvents.executorUnavailable.get());
        this.raspProcessingDeactivated.set(droppedEvents.raspProcessingDeactivated.get());
        this.rxssDetectionDeactivated.set(droppedEvents.rxssDetectionDeactivated.get());
    }

    public AtomicInteger getUnsupportedContentType() {
        return unsupportedContentType;
    }

    public AtomicInteger getNrInternalEvent() {
        return nrInternalEvent;
    }

    public AtomicInteger getCsecInternalEvent() {
        return csecInternalEvent;
    }

    public void incrementUnsupportedContentType() {
        unsupportedContentType.incrementAndGet();
    }

    public void incrementNrInternalEvent() {
        nrInternalEvent.incrementAndGet();
    }

    public void incrementCsecInternalEvent() {
        csecInternalEvent.incrementAndGet();
    }

    public AtomicInteger getExecutorUnavailable() {
        return executorUnavailable;
    }

    public void incrementExecutorUnavailable() {
        executorUnavailable.incrementAndGet();
    }

    public AtomicInteger getRaspProcessingDeactivated() {
        return raspProcessingDeactivated;
    }

    public void incrementRaspProcessingDeactivated() {
        raspProcessingDeactivated.incrementAndGet();
    }

    public AtomicInteger getRxssDetectionDeactivated() {
        return rxssDetectionDeactivated;
    }

    public void incrementRxssDetectionDeactivated() {
        rxssDetectionDeactivated.incrementAndGet();
    }

    public void reset(){
        unsupportedContentType.set(0);
        nrInternalEvent.set(0);
        csecInternalEvent.set(0);
        executorUnavailable.set(0);
        raspProcessingDeactivated.set(0);
        rxssDetectionDeactivated.set(0);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
