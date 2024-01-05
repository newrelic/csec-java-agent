package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class EventStats {

    private AtomicInteger processed;

    private AtomicInteger sent;

    private AtomicInteger rejected;

    private AtomicInteger errorCount;

    public EventStats() {
        this.processed = new AtomicInteger(0);
        this.sent = new AtomicInteger(0);
        this.rejected = new AtomicInteger(0);
        this.errorCount = new AtomicInteger(0);
    }

    public EventStats(EventStats eventStats) {
        this.processed = new AtomicInteger(eventStats.processed.intValue());
        this.sent = new AtomicInteger(eventStats.sent.intValue());
        this.rejected = new AtomicInteger(eventStats.rejected.intValue());
        this.errorCount = new AtomicInteger(eventStats.errorCount.intValue());
    }

    public AtomicInteger getProcessed() {
        return processed;
    }

    public void setProcessed(AtomicInteger processed) {
        this.processed = processed;
    }

    public AtomicInteger getSent() {
        return sent;
    }

    public void setSent(AtomicInteger sent) {
        this.sent = sent;
    }

    public AtomicInteger getRejected() {
        return rejected;
    }

    public void setRejected(AtomicInteger rejected) {
        this.rejected = rejected;
    }

    public int incrementRejectedCount(){
        return this.rejected.incrementAndGet();
    }

    public int incrementSentCount(){
        return this.sent.incrementAndGet();
    }

    public int incrementProcessedCount(){
        return this.processed.incrementAndGet();
    }

    public int incrementErrorCount(){
        return this.errorCount.incrementAndGet();
    }

    public AtomicInteger getErrorCount() {
        return errorCount;
    }

    public void setErrorCount(AtomicInteger errorCount) {
        this.errorCount = errorCount;
    }

    public void reset(){
        this.processed.set(0);
        this.sent.set(0);
        this.errorCount.set(0);
        this.rejected.set(0);
    }



    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
