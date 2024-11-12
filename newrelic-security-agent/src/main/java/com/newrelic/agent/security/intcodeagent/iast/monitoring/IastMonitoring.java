package com.newrelic.agent.security.intcodeagent.iast.monitoring;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class IastMonitoring {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private final AtomicBoolean harvestActive = new AtomicBoolean(false);
    private final AtomicInteger harvestCycleCount = new AtomicInteger();
    private final AtomicInteger remainingHarvestRequests = new AtomicInteger();
    private final AtomicInteger requestHarvested = new AtomicInteger();

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

    public static void sampleData() {
        if(IastMonitoring.getInstance().getHarvestCycleCount() % 12 == 0){
            IastMonitoring.getInstance().setRemainingHarvestRequests(0);
        }
        IastMonitoring.getInstance().setHarvestActive(true);
        IastMonitoring.getInstance().setRemainingHarvestRequests(IastMonitoring.getInstance().getRemainingHarvestRequests() + 5);
        IastMonitoring.getInstance().setRequestHarvested(0);
        IastMonitoring.getInstance().incrementHarvestCycleCount();
        logger.log( LogLevel.FINEST, String.format("IAST Monitoring: Sampling of Data Started for cycle %s can harvest %s requests", IastMonitoring.getInstance().getHarvestCycleCount(), IastMonitoring.getInstance().getRemainingHarvestRequests()), IastMonitoring.class.getName());
    }

    public static void collectSampleIfHarvested() {
        if(AgentConfig.getInstance().getAgentMode().getIastScan().getMonitoringMode().getHarvesting().get()) {

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

    public static boolean shouldProcessInterception() {
        if(AgentConfig.getInstance().getAgentMode().getIastScan().getMonitoring()) {
            return IastMonitoring.getInstance().getHarvestActive() && NewRelicSecurity.getAgent().getSecurityMetaData().customAttributeContainsKey("HARVEST") && NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("HARVEST", Boolean.class);
        } else {
            return true;
        }
    }

}