package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class EventStats {

    private EventMetric eventSender = new EventMetric();

    private EventMetric iastEvents = new EventMetric();

    private EventMetric dispatcher = new EventMetric();

    private DroppedEvents droppedDueTo = new DroppedEvents();

    private EventMetric lowSeverityEvents = new EventMetric();

    private EventMetric exitEvents = new EventMetric();

    public EventStats() {
    }

    public EventStats(EventStats eventStats) {
        this.eventSender = new EventMetric(eventStats.eventSender);
        this.iastEvents = new EventMetric(eventStats.iastEvents);
        this.dispatcher = new EventMetric(eventStats.dispatcher);
        this.droppedDueTo = new DroppedEvents(eventStats.droppedDueTo);
        this.lowSeverityEvents = new EventMetric(eventStats.lowSeverityEvents);
        this.exitEvents = new EventMetric(eventStats.exitEvents);
    }

    public void reset(){
        this.lowSeverityEvents.reset();
        this.eventSender.reset();
        this.iastEvents.reset();
        this.dispatcher.reset();
        this.exitEvents.reset();
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public EventMetric getLowSeverityEvents() {
        return lowSeverityEvents;
    }

    public EventMetric getEventSender() {
        return eventSender;
    }

    public EventMetric getIastEvents() {
        return iastEvents;
    }

    public EventMetric getDispatcher() {
        return dispatcher;
    }

    public DroppedEvents getDroppedDueTo() {
        return droppedDueTo;
    }

    public EventMetric getExitEvents() {
        return exitEvents;
    }
}
