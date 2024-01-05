package com.nr.agent.security.instrumentation.graalvm22;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.oracle.truffle.polyglot")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GraalVMTest {
    @Test
    public void testEval(){
        String script = "print(\"Pikachu\")";
        Context context = Context.create("js");
        context.eval("js", script);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.oracle.truffle.polyglot.PolyglotContextImpl", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "eval", operation.getMethodName());
    }

    @Test
    public void testEval1(){
        String script = "print(\"Ash\")";
        Context context = Context.create("js");
        context.eval(Source.create("js", script));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.oracle.truffle.polyglot.PolyglotContextImpl", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "eval", operation.getMethodName());
    }

    @Test
    public void testEval2(){
        String script = "print(\"Togepe\")";
        Context context = Context.newBuilder("js").build();
        context.eval(Source.create("js", script));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.oracle.truffle.polyglot.PolyglotContextImpl", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "eval", operation.getMethodName());
    }
}
