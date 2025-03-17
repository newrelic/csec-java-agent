package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class IastExclusionUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private final TTLMap<String, Set<String>> encounteredTraces = new TTLMap<>("encounteredTraces");

    private final TTLMap<String, Boolean> skippedTraces = new TTLMap<>("skippedTraces");

    private final Set<String> skippedTraceApis = ConcurrentHashMap.newKeySet();

    private IastExclusionUtils() {
    }

    public boolean skippedTrace(String traceId) {
        return skippedTraces.containsKey(traceId);
    }

    public boolean skipTraceApi(String id) {
        return skippedTraceApis.contains(id);
    }

    private static final class InstanceHolder {
        static final IastExclusionUtils instance = new IastExclusionUtils();
    }

    public static IastExclusionUtils getInstance() {
        return InstanceHolder.instance;
    }

    public void addEncounteredTrace(String traceId, String operationApiId) {
        Set<String> operationApiIds = encounteredTraces.get(traceId);
        if (operationApiIds == null) {
            operationApiIds = ConcurrentHashMap.newKeySet();
            encounteredTraces.put(traceId, operationApiIds);
        }
        operationApiIds.add(operationApiId);
        updateSkippedTraceApis(traceId, operationApiId);
    }

    public void registerSkippedTrace(String traceId) {
        skippedTraces.put(traceId, true);
        updateSkippedTraceApis(traceId);
    }

    private void updateSkippedTraceApis(String traceId) {
        Set<String> operationApiIds = encounteredTraces.get(traceId);
        if (operationApiIds != null) {
            skippedTraceApis.addAll(operationApiIds);
            logger.log(LogLevel.FINER, String.format("Adding trace to skip list: %s with following api ids: %s", skippedTraceApis, operationApiIds), IastExclusionUtils.class.getName());
        }
    }

    private void updateSkippedTraceApis(String traceId, String operationApiId) {
        if (skippedTraces.containsKey(traceId)) {
            skippedTraceApis.add(operationApiId);
            logger.log(LogLevel.FINER, "Adding api id to skip list: " + skippedTraceApis, IastExclusionUtils.class.getName());
        }
    }


}
