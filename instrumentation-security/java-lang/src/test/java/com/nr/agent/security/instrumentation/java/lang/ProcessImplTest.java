package com.nr.agent.security.instrumentation.java.lang;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;
import com.newrelic.security.test.marker.*;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "java.lang.ProcessImpl_Instrumentation")
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class ProcessImplTest {
    private String cmd = "/bin/sh -c ls";
    private String cmd2 = "ls";

    @Test
    public void testStart() throws IOException, InterruptedException {
        callExecute();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        ForkExecOperation operation = (ForkExecOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", cmd, operation.getCommand());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SYSTEM_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "java.lang.ProcessImpl", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "start", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    public void callExecute() throws InterruptedException, IOException {
        StringBuffer output = new StringBuffer();
        Process pr = Runtime.getRuntime().exec(cmd);
        pr.waitFor();
        BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        System.out.println(output);
    }

    @Test
    public void testProcessBuilderStart() {
        callProcessBuilderStart();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        ForkExecOperation operation = (ForkExecOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", cmd2, operation.getCommand());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SYSTEM_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "java.lang.ProcessImpl", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "start", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    public void callProcessBuilderStart() {
        StringBuffer output = new StringBuffer();
        try {
            ProcessBuilder builder = new ProcessBuilder(cmd2);
            Process pr = builder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println(output);
    }

}
