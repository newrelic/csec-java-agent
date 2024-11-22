package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class ThreadPoolStats {

    private ThreadPoolActiveStat dispatcher;

    private ThreadPoolActiveStat eventSender;

    private ThreadPoolActiveStat fileLogger;

    private ThreadPoolActiveStat iastHttpRequestProcessor;

    private ThreadPoolActiveStat controlCommandProcessor;

    public ThreadPoolStats() {
    }

    public ThreadPoolStats(ThreadPoolStats threadPoolStats) {
        this.dispatcher = new ThreadPoolActiveStat(threadPoolStats.dispatcher.getActiveThreadCount(), threadPoolStats.dispatcher.getCurrentQueueSize());
        this.eventSender = new ThreadPoolActiveStat(threadPoolStats.eventSender.getActiveThreadCount(), threadPoolStats.eventSender.getCurrentQueueSize());
        this.fileLogger = new ThreadPoolActiveStat(threadPoolStats.fileLogger.getActiveThreadCount(), threadPoolStats.fileLogger.getCurrentQueueSize());
        this.iastHttpRequestProcessor = new ThreadPoolActiveStat(threadPoolStats.iastHttpRequestProcessor.getActiveThreadCount(), threadPoolStats.iastHttpRequestProcessor.getCurrentQueueSize());
        this.controlCommandProcessor = new ThreadPoolActiveStat(threadPoolStats.controlCommandProcessor.getActiveThreadCount(), threadPoolStats.controlCommandProcessor.getCurrentQueueSize());

    }

    public ThreadPoolActiveStat getDispatcher() {
        return dispatcher;
    }

    public ThreadPoolActiveStat getEventSender() {
        return eventSender;
    }

    public ThreadPoolActiveStat getFileLogger() {
        return fileLogger;
    }

    public ThreadPoolActiveStat getIastHttpRequestProcessor() {
        return iastHttpRequestProcessor;
    }

    public ThreadPoolActiveStat getControlCommandProcessor() {
        return controlCommandProcessor;
    }

    public void setDispatcher(ThreadPoolActiveStat dispatcher) {
        this.dispatcher = dispatcher;
    }

    public void setEventSender(ThreadPoolActiveStat eventSender) {
        this.eventSender = eventSender;
    }

    public void setFileLogger(ThreadPoolActiveStat fileLogger) {
        this.fileLogger = fileLogger;
    }

    public void setIastHttpRequestProcessor(ThreadPoolActiveStat iastHttpRequestProcessor) {
        this.iastHttpRequestProcessor = iastHttpRequestProcessor;
    }

    public void setControlCommandProcessor(ThreadPoolActiveStat controlCommandProcessor) {
        this.controlCommandProcessor = controlCommandProcessor;
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
