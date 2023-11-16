package com.newrelic.agent.security.instrumentator.dispatcher;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IdentifierEnvs;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.UserClassEntity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.*;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.HashMap;

public class DispatcherTest {

    private final String CLASS_NAME = "className";
    private final String METHOD_NAME = "methodName";

    @Mock
    private FileLoggerThreadPool logger;


    @BeforeClass
    public static void beforeClass() {
        CollectorConfig collectorConfig = Mockito.mock(CollectorConfig.class);
        Identifier identifier = new Identifier();
        identifier.setKind(IdentifierEnvs.HOST);
        AgentInfo.getInstance().setIdentifier(identifier);
        AgentInfo.getInstance().generateAppInfo(collectorConfig);
        AgentInfo.getInstance().initialiseHC();
    }

    @Test
    public void testProcessNullEvent() throws Exception {
        Dispatcher dispatcher = new Dispatcher(null, Mockito.mock(SecurityMetaData.class));
        Assert.assertNull(dispatcher.call());
    }

}
