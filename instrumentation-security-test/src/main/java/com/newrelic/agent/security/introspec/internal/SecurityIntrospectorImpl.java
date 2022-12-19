package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.Agent;
import com.newrelic.agent.bridge.AgentBridge;
import com.newrelic.agent.instrumentation.InstrumentationImpl;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.service.ServiceFactory;
import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SecurityIntrospectorImpl implements SecurityIntrospector {

    //    private IntrospectData data;
    List<AbstractOperation> operations = new ArrayList<>();

    List<ExitEventBean> exitEvents = new ArrayList<>();

    private SecurityIntrospectorImpl() {
//        data = new IntrospectData();
    }

    public static SecurityIntrospectorImpl createIntrospector(Map<String, Object> config) {
        initialize(config);
        SecurityIntrospectorImpl impl = new SecurityIntrospectorImpl();
//        ServiceFactory.getTransactionService().addCustomTransactionListener(impl);
        return impl;
    }

    private static IntrospectorServiceManager initialize(Map<String, Object> config) {
        IntrospectorServiceManager manager = IntrospectorServiceManager.createAndInitialize(config);
        try {
            manager.start();
        } catch (Exception e) {
            // app will not work correctly
        }

        // initialize services / APIs
        com.newrelic.api.agent.NewRelicApiImplementation.initialize();
        com.newrelic.agent.PrivateApiImpl.initialize(Agent.LOG);
        AgentBridge.instrumentation = new InstrumentationImpl(Agent.LOG);
        return manager;
    }

    @Override
    public Iterator<AbstractOperation> getOperations() {
        return operations.iterator();
    }

    @Override
    public void addExitEvent(AbstractOperation operation) {
        this.operations.add(operation);
    }

    @Override
    public Iterator<ExitEventBean> getExitEvents() {
        return exitEvents.iterator();
    }

    @Override
    public void addExitEvent(ExitEventBean exitEvent) {
        exitEvents.add(exitEvent);
    }

    public void clearSpanEvents() {
        IntrospectorSpanEventService service = (IntrospectorSpanEventService) ServiceFactory.getServiceManager().getSpanEventsService();
        service.clearReservoir();
    }

    @Override
    public void clear() {
        this.operations.clear();
        this.exitEvents.clear();
        IntrospectorInsightsService customEventService = (IntrospectorInsightsService) ServiceFactory.getServiceManager().getInsights();
        customEventService.clear();
        IntrospectorErrorService errorService = (IntrospectorErrorService) ServiceFactory.getRPMService().getErrorService();
        errorService.clear();
        IntrospectorStatsService statsService = (IntrospectorStatsService) ServiceFactory.getStatsService();
        statsService.clear();
        IntrospectorTransactionTraceService traceService = (IntrospectorTransactionTraceService) ServiceFactory.getTransactionTraceService();
        traceService.clear();
        clearSpanEvents();
    }
}
