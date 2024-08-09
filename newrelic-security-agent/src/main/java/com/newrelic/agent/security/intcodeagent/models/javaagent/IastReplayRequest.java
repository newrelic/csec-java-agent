package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class IastReplayRequest {

    private AtomicInteger receivedControlCommands = new AtomicInteger();

    private AtomicInteger processedControlCommands = new AtomicInteger();

    private AtomicInteger pendingControlCommands = new AtomicInteger();

    private AtomicInteger replayRequestGenerated = new AtomicInteger();

    private AtomicInteger replayRequestExecuted = new AtomicInteger();

    private AtomicInteger replayRequestSucceeded = new AtomicInteger();

    private AtomicInteger replayRequestFailed = new AtomicInteger();

    private AtomicInteger replayRequestRejected = new AtomicInteger();

    public IastReplayRequest() {
    }

    public IastReplayRequest(IastReplayRequest iastReplayRequest) {
        this.receivedControlCommands.set(iastReplayRequest.getReceivedControlCommands().get());
        this.processedControlCommands.set(iastReplayRequest.getProcessedControlCommands().get());
        this.pendingControlCommands.set(iastReplayRequest.getPendingControlCommands().get());
        this.replayRequestGenerated.set(iastReplayRequest.getReplayRequestGenerated().get());
        this.replayRequestExecuted.set(iastReplayRequest.getReplayRequestExecuted().get());
        this.replayRequestSucceeded.set(iastReplayRequest.getReplayRequestSucceeded().get());
        this.replayRequestFailed.set(iastReplayRequest.getReplayRequestFailed().get());
        this.replayRequestRejected.set(iastReplayRequest.getReplayRequestRejected().get());
    }

    public AtomicInteger getReceivedControlCommands() {
        return receivedControlCommands;
    }

    public AtomicInteger getProcessedControlCommands() {
        return processedControlCommands;
    }

    public AtomicInteger getPendingControlCommands() {
        return pendingControlCommands;
    }

    public AtomicInteger getReplayRequestGenerated() {
        return replayRequestGenerated;
    }

    public AtomicInteger getReplayRequestExecuted() {
        return replayRequestExecuted;
    }

    public AtomicInteger getReplayRequestSucceeded() {
        return replayRequestSucceeded;
    }

    public AtomicInteger getReplayRequestFailed() {
        return replayRequestFailed;
    }

    public AtomicInteger getReplayRequestRejected() {
        return replayRequestRejected;
    }

    public int incrementReceivedControlCommands() {
        return receivedControlCommands.incrementAndGet();
    }

    public int incrementProcessedControlCommands() {
        return processedControlCommands.incrementAndGet();
    }

    public int incrementPendingControlCommands() {
        return pendingControlCommands.incrementAndGet();
    }

    public int incrementReplayRequestGenerated() {
        return replayRequestGenerated.incrementAndGet();
    }

    public int incrementReplayRequestExecuted() {
        return replayRequestExecuted.incrementAndGet();
    }

    public int incrementReplayRequestSucceeded() {
        return replayRequestSucceeded.incrementAndGet();
    }

    public int incrementReplayRequestFailed() {
        return replayRequestFailed.incrementAndGet();
    }

    public int incrementReplayRequestRejected() {
        return replayRequestRejected.incrementAndGet();
    }

    public void incrementPendingControlCommandsBy(int count) {
        pendingControlCommands.addAndGet(count);
    }

    public void reset() {
        receivedControlCommands.set(0);
        processedControlCommands.set(0);
        pendingControlCommands.set(0);
        replayRequestGenerated.set(0);
        replayRequestExecuted.set(0);
        replayRequestSucceeded.set(0);
        replayRequestFailed.set(0);
        replayRequestRejected.set(0);
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }


}
