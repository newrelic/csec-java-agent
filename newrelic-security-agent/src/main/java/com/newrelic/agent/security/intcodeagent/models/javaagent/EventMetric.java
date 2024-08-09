package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class EventMetric {

    private AtomicInteger submitted = new AtomicInteger(0);

    private AtomicInteger completed = new AtomicInteger(0);

    private AtomicInteger rejected = new AtomicInteger(0);

    private AtomicInteger error = new AtomicInteger(0);

    public EventMetric() {
    }

    public EventMetric(EventMetric eventMetric) {
        this.submitted.set(eventMetric.submitted.get());
        this.completed.set(eventMetric.completed.get());
        this.rejected.set(eventMetric.rejected.get());
        this.error.set(eventMetric.error.get());
    }

    public AtomicInteger getSubmitted() {
        return submitted;
    }

    public AtomicInteger getCompleted() {
        return completed;
    }

    public AtomicInteger getRejected() {
        return rejected;
    }

    public AtomicInteger getError() {
        return error;
    }

    public int incrementSubmitted() {
        return submitted.incrementAndGet();
    }

    public int incrementCompleted() {
        return completed.incrementAndGet();
    }

    public int incrementRejected() {
        return rejected.incrementAndGet();
    }

    public int incrementError() {
        return error.incrementAndGet();
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public void reset(){
        submitted.set(0);
        completed.set(0);
        rejected.set(0);
        error.set(0);
    }
}
