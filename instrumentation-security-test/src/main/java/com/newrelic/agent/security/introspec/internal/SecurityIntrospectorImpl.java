package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.Agent;
import com.newrelic.agent.bridge.AgentBridge;
import com.newrelic.agent.instrumentation.InstrumentationImpl;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.schema.Operation;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SecurityIntrospectorImpl implements SecurityIntrospector {

    //    private IntrospectData data;
    List<Operation> operations = new ArrayList<>();

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
//        AgentConfig.getInstance().instantiate();
//        K2ServiceInfo info = new K2ServiceInfo();
//        info.setValidatorServiceEndpointURL("ws://192.168.5.138:54321");
//        info.setResourceServiceEndpointURL("http://192.168.5.138:54322");
//        CollectorConfig conf = new CollectorConfig();
//        conf.setK2ServiceInfo(info);
//        AgentConfig.getInstance().setConfig(conf);

//        URL securityJarURL = null;
//        try {
//            securityJarURL = EmbeddedJarFilesImpl.INSTANCE.getJarFileInAgent(BootstrapLoader.NEWRELIC_SECURITY_AGENT).toURI().toURL();
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//        com.newrelic.api.agent.security.Agent.getInstance().refreshState(securityJarURL);

        AgentBridge.instrumentation = new InstrumentationImpl(Agent.LOG);
        return manager;
    }

    @Override
    public Iterator<Operation> getOperations() {
        return operations.iterator();
    }

    @Override
    public void addOperation(Operation operation) {
        this.operations.add(operation);
    }

    @Override
    public void clear() {
        this.operations.clear();
    }
}
