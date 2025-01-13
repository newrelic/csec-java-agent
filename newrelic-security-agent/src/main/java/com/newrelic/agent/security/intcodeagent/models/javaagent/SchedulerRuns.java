package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class SchedulerRuns {

    private AtomicInteger iastFileCleaner = new AtomicInteger();

    private AtomicInteger lowPriorityFilterCleaner = new AtomicInteger();

    private AtomicInteger dailyLogRollover = new AtomicInteger();

    private AtomicInteger websocketReconnector = new AtomicInteger();

    public SchedulerRuns() {
    }

    public SchedulerRuns(SchedulerRuns schedulerRuns) {
        iastFileCleaner.set(schedulerRuns.iastFileCleaner.get());
        lowPriorityFilterCleaner.set(schedulerRuns.lowPriorityFilterCleaner.get());
        dailyLogRollover.set(schedulerRuns.dailyLogRollover.get());
        websocketReconnector.set(schedulerRuns.websocketReconnector.get());
    }

    public AtomicInteger getIastFileCleaner() {
        return iastFileCleaner;
    }

    public AtomicInteger getLowPriorityFilterCleaner() {
        return lowPriorityFilterCleaner;
    }

    public AtomicInteger getDailyLogRollover() {
        return dailyLogRollover;
    }

    public AtomicInteger getWebsocketReconnector() {
        return websocketReconnector;
    }

    public int incrementIastFileCleaner() {
        return iastFileCleaner.incrementAndGet();
    }

    public int incrementLowPriorityFilterCleaner() {
        return lowPriorityFilterCleaner.incrementAndGet();
    }

    public int incrementDailyLogRollover() {
        return dailyLogRollover.incrementAndGet();
    }

    public int incrementWebsocketReconnector() {
        return websocketReconnector.incrementAndGet();
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public void reset() {
        iastFileCleaner.set(0);
        lowPriorityFilterCleaner.set(0);
        dailyLogRollover.set(0);
        websocketReconnector.set(0);
    }
}
