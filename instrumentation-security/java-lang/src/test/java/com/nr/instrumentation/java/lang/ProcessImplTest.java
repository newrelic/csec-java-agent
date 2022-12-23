package com.nr.instrumentation.java.lang;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
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
    @Test
    public void testProcess() throws ClassNotFoundException, JsonProcessingException {
        callExecute();
        // Assert the event category and executed parameter
        List<AbstractOperation> operations = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("operations", List.class);
        Assert.assertTrue("No operations detected", operations.size() > 0);
        for (AbstractOperation operation : operations) {
            System.out.println("Operation : " + new ObjectMapper().writeValueAsString(operation));
        }
    }

    @Trace(dispatcher = true)
    public void callExecute() {
        String[] cmd = {
                "/bin/sh",
                "-c",
                "ls"
        };

        StringBuffer output = new StringBuffer();
        try {
            Process pr = Runtime.getRuntime().exec(cmd);
            pr.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                output.append(line + "<br/>");
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        System.out.println(output);
    }

}
