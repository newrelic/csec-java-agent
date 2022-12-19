package com.nr.instrumentation.java.lang.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "java.lang")
public class ProcessImplTest {
    @Test
    public void testProcess() {
//        NewRelicSecurity.getAgent();
        String[] cmd = {
                "/bin/sh",
                "-c",
                "ls"
        };

        StringBuffer output = new StringBuffer();
        ProcessBuilder builder = new ProcessBuilder(cmd);
        try {
            Process pr = builder.start();
//            pr = Runtime.getRuntime().exec(cmd);
            pr.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                output.append(line + "<br/>");
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

//        Process p;
//        try {
//            p = Runtime.getRuntime().exec(cmd);
//            p.waitFor();
//            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
//
//            String line = "";
//            while ((line = reader.readLine()) != null) {
//                output.append(line + "<br/>");
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        System.out.println(output);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        // Assert the event category and executed parameter
        if (introspector.getOperations().hasNext()){
            System.out.println(introspector.getOperations().next());
        }
        else {
            System.out.println("no operations");
        }


    }

}
