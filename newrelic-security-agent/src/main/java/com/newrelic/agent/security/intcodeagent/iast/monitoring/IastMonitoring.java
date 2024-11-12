package com.newrelic.agent.security.intcodeagent.iast.monitoring;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class IastMonitoring {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private final AtomicBoolean harvestActive = new AtomicBoolean(false);
    private final AtomicInteger harvestCycleCount = new AtomicInteger();
    private final AtomicInteger remainingHarvestRequests = new AtomicInteger();
    private final AtomicInteger requestHarvested = new AtomicInteger();

    private Map<String, Integer> harvestedTraceId = new ConcurrentHashMap<>();
    private Map<String, Integer> harvestedAPI = new ConcurrentHashMap<>();


    private static final class InstanceHolder {
        static final IastMonitoring instance = new IastMonitoring();
    }

    private IastMonitoring() {
    }

    public static IastMonitoring getInstance() {
        return InstanceHolder.instance;
    }

    public boolean getHarvestActive() {
        return harvestActive.get();
    }

    public void setHarvestActive(boolean harvestActive) {
        this.harvestActive.set(harvestActive);
    }

    public int getHarvestCycleCount() {
        return harvestCycleCount.get();
    }

    public void incrementHarvestCycleCount() {
        harvestCycleCount.incrementAndGet();
    }

    public int decrementRemainingHarvestRequests() {
        return remainingHarvestRequests.decrementAndGet();
    }

    public void setRemainingHarvestRequests(int remainingHarvestRequests) {
        this.remainingHarvestRequests.set(remainingHarvestRequests);
    }

    public void setRequestHarvested(int requestHarvested) {
        this.requestHarvested.set(requestHarvested);
    }

    public int getRequestHarvested() {
        return requestHarvested.get();
    }

    public void incrementRequestHarvested() {
        requestHarvested.incrementAndGet();
    }

    public int getRemainingHarvestRequests() {
        return remainingHarvestRequests.get();
    }

    public Map<String, Integer> getHarvestedTraceId() {
        return harvestedTraceId;
    }

    public void incrementHarvestedTraceId(String traceId) {
        harvestedTraceId.put(traceId, harvestedTraceId.getOrDefault(traceId, 0) + 1);
    }

    public Map<String, Integer> getHarvestedAPI() {
        return harvestedAPI;
    }

    public void incrementHarvestedAPI(String api) {
        harvestedAPI.put(api, harvestedAPI.getOrDefault(api, 0) + 1);
    }

    public static void sampleData() {
        logger.log( LogLevel.FINEST, String.format("following are the harvested APIs in last harvest cycle : %s", IastMonitoring.getInstance().getHarvestedAPI()), IastMonitoring.class.getName());
        if(IastMonitoring.getInstance().getHarvestCycleCount() % 12 == 0){
            IastMonitoring.getInstance().setRemainingHarvestRequests(0);
        }
        IastMonitoring.getInstance().setHarvestActive(true);
        IastMonitoring.getInstance().setRemainingHarvestRequests(IastMonitoring.getInstance().getRemainingHarvestRequests() + 5);
        IastMonitoring.getInstance().setRequestHarvested(0);
        IastMonitoring.getInstance().incrementHarvestCycleCount();
        IastMonitoring.getInstance().getHarvestedAPI().clear();
        logger.log( LogLevel.FINEST, String.format("IAST Monitoring: Sampling of Data Started for cycle %s can harvest %s requests", IastMonitoring.getInstance().getHarvestCycleCount(), IastMonitoring.getInstance().getRemainingHarvestRequests()), IastMonitoring.class.getName());
    }

    public static void resetEventSampler() {
        IastMonitoring.getInstance().setRemainingHarvestRequests(0);
        IastMonitoring.getInstance().getHarvestedAPI().clear();
        IastMonitoring.getInstance().getHarvestedTraceId().clear();
        logger.log( LogLevel.FINEST, String.format("IAST Monitoring: Sampling of Data Stopped for cycle %s", IastMonitoring.getInstance().getHarvestCycleCount()), IastMonitoring.class.getName());
    }


    public static void collectSampleIfHarvested() {
        if(AgentConfig.getInstance().getAgentMode().getIastScan().getMonitoringMode().getHarvesting().get()) {

            if(NewRelicSecurity.getAgent().getSecurityMetaData() != null) {
                SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                if(StringUtils.isNotBlank(securityMetaData.getRequest().getUrl())){
                    IastMonitoring.getInstance().incrementHarvestedAPI(securityMetaData.getRequest().getUrl());
                }
            }

            AgentConfig.getInstance().getAgentMode().getIastScan().getMonitoringMode().getHarvesting().set(false);
            NewRelicSecurity.getAgent().getSecurityMetaData().removeCustomAttribute("HARVEST");
            IastMonitoring.getInstance().incrementRequestHarvested();
            int remaining = IastMonitoring.getInstance().decrementRemainingHarvestRequests();
            if(remaining <= 0){
                IastMonitoring.getInstance().setHarvestActive(false);
                logger.log(LogLevel.FINEST, "IAST Monitoring: Harvesting Completed", IastMonitoring.class.getName());
            }
            logger.log( LogLevel.FINEST, String.format("IAST Monitoring: %s:%s Sample collected", IastMonitoring.getInstance().getHarvestCycleCount(), IastMonitoring.getInstance().getRequestHarvested()), IastMonitoring.class.getName());
        }
    }

    public static void registerTraceHarvested(String traceId) {
        IastMonitoring.getInstance().incrementHarvestedTraceId(traceId);
    }

    public static boolean eventQuotaReached(String traceId) {
        return IastMonitoring.getInstance().getHarvestedTraceId().getOrDefault(traceId, 0) >= 100;
    }

    public static boolean shouldProcessInterception() {
        if(AgentConfig.getInstance().getAgentMode().getIastScan().getMonitoring()) {
            return IastMonitoring.getInstance().getHarvestActive() && NewRelicSecurity.getAgent().getSecurityMetaData().customAttributeContainsKey("HARVEST") && NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("HARVEST", Boolean.class);
        } else {
            return true;
        }
    }

}
