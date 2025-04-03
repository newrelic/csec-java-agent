package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IntCodeControlCommand;
import org.junit.Assert;

import org.junit.Test;
import org.mockito.Mockito;
import java.util.Arrays;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;

public class RestRequestProcessorTest {

    @Test
    public void reqProcessingTest() throws InterruptedException {
        // controlCommand size is less than 2
        IntCodeControlCommand cc = Mockito.mock(IntCodeControlCommand.class);
        Assert.assertTrue(new RestRequestProcessor(cc, 1).call());

        Mockito.verify(cc, atLeastOnce()).getArguments();
        Mockito.clearInvocations(cc);
        Mockito.clearAllCaches();
    }

    @Test
    public void reqProcessingFailTest() throws InterruptedException {
        // fails in JSONProcessing since the fuzz request is invalid
        AgentInfo.getInstance().setAgentActive(false);

        IntCodeControlCommand cc = Mockito.mock(IntCodeControlCommand.class);
        doReturn(Arrays.asList("arg", "arg", "arg")).when(cc).getArguments();
        Assert.assertFalse(new RestRequestProcessor(cc, 1).call());

        Mockito.verify(cc, atLeastOnce()).getArguments();
        Mockito.clearInvocations(cc);
        Mockito.clearAllCaches();
    }

    @Test
    public void reqProcessingPassTest() throws InterruptedException {
//        AgentInfo.getInstance().setAgentActive(true);
////        AgentConfig.getInstance().setNRSecurityEnabled(true);
//
//        String arg1 = "{\"clientIP\":\"127.0.0.1\",\"clientPort\":\"0\",\"contentType\":\"text/plain\",\"requestURI\":\"/url\",\"body\":\"body\",\"method\":\"POST\",\"url\":\"/url\",\"headers\":{\"content-type\":\"text/plain;\",\"nr-csec-parent-id\":\"parent-id\",\"nr-csec-fuzz-request-id\":\"HTTP_REQUEST--parent-id:IAST:native:__K2UEB0__:IAST:body:IAST:VULNERABLE:IAST:1:IAST: :IAST:body\"},\"whitelistedIPs\":[\"localhost\"],\"protocol\":\"http\",\"originalTraceMeta\":{\"applicationUUID\":\"dummy\"},\"serverPort\":8000}";
//        IntCodeControlCommand cc = Mockito.mock(IntCodeControlCommand.class);
//        doReturn(Arrays.asList(arg1, "arg", "arg")).when(cc).getArguments();
//        Assert.assertTrue(new RestRequestProcessor(cc, 1).call());
//
//        Mockito.verify(cc, atLeastOnce()).getArguments();
//        Mockito.verify(cc, atLeastOnce()).getId();
//        Mockito.clearInvocations(cc);
//        Mockito.clearAllCaches();
    }

}
