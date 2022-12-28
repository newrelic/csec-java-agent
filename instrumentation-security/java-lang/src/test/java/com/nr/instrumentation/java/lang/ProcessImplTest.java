package com.nr.instrumentation.java.lang;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "java.lang.ProcessImpl_Instrumentation")
public class ProcessImplTest {
    private String cmd = "/bin/sh -c ls";

    @Test
    public void testStart() {
        callExecute();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        ForkExecOperation operation = (ForkExecOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", cmd, operation.getCommand());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SYSTEM_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", operation.getClassName(), "java.lang.ProcessImpl");
        Assert.assertEquals("Invalid executed method name.", operation.getMethodName(), "start");
    }

    @Trace(dispatcher = true)
    public void callExecute() {
        StringBuffer output = new StringBuffer();
        try {
            Process pr = Runtime.getRuntime().exec(cmd);
            pr.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        System.out.println(output);
    }

}
