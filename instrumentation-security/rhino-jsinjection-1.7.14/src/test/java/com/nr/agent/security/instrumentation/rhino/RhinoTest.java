package com.nr.agent.security.instrumentation.rhino;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Script;
import org.mozilla.javascript.Scriptable;

import java.io.FileReader;
import java.io.IOException;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "org.mozilla.javascript" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RhinoTest {

    @Trace
    private static String callFunctionCall() {
        Context rhino = Context.enter();
        String script = "function greet() { return 'Hello, Rhino!'; }";
        try {
            Scriptable scope = rhino.initStandardObjects();
            rhino.evaluateString(scope, script, "<cmd>", 1, null);
            Object greet = scope.get("greet", scope);
            if (greet instanceof Function func) {
                Object result = func.call(rhino, scope, scope, new Object[] {});
                System.out.println(Context.toString(result));
            }
        } finally {
            Context.exit();
        }
        return script;
    }

    @Trace
    private static String callExec() {
        Context rhino = Context.enter();
        String script = "function greet() { return 'Hello, World!'; }";
        try {
            Scriptable scope = rhino.initStandardObjects();
            Script compiledScript = rhino.compileString(script, "<cmd>", 1, null);
            compiledScript.exec(rhino, scope);
            Object greet = scope.get("greet", scope);
            if (greet instanceof Function func) {
                Object result = func.call(rhino, scope, scope, new Object[] {});
                System.out.println(Context.toString(result));
            }
        } finally {
            Context.exit();
        }
        return script;
    }

    @Trace
    private static String callExecWithReader() throws IOException {
        Context rhino = Context.enter();
        String script = "var fun1 = function(name) { return 'Hi, ' + name; };";
        try {
            Scriptable scope = rhino.initStandardObjects();
            Script compiledScript = rhino.compileReader(new FileReader("src/test/resources/script.js"), "<cmd>", 1, null);
            compiledScript.exec(rhino, scope);
            Object greet = scope.get("fun1", scope);
            if (greet instanceof Function func) {
                Object result = func.call(rhino, scope, scope, new Object[] {"rhino"});
                System.out.println(Context.toString(result));
            }
        } finally {
            Context.exit();
        }
        return script;
    }

    @Trace
    private static String callCompileFunction() throws IOException {
        Context rhino = Context.enter();
        String script = "function(name) { return 'Hi, ' + name; };";
        try {
            Scriptable scope = rhino.initStandardObjects();
            Function func = rhino.compileFunction(scope, script, "<cmd>", 1, null);
            Object result = func.call(rhino, scope, scope, new Object[] {"Ash"});
            System.out.println(Context.toString(result));
        } finally {
            Context.exit();
        }
        return script;
    }

    @Trace
    private static String callFunctionCallWithReader() throws IOException {
        Context rhino = Context.enter();
        String script = "var fun1 = function(name) { return 'Hi, ' + name; };";
        try {
            Scriptable scope = rhino.initStandardObjects();
            rhino.evaluateReader(scope, new FileReader("src/test/resources/script.js"), "<cmd>", 1, null);
            Object greet = scope.get("fun1", scope);
            if (greet instanceof Function func) {
                Object result = func.call(rhino, scope, scope, new String[] { "hero" });
                System.out.println(Context.toString(result));
            }
        } finally {
            Context.exit();
        }
        return script;
    }

    @Test
    public void testExec(){
        String script = callExec();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", Script.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "exec", operation.getMethodName());
    }

    @Test
    public void testExecWithReader() throws IOException {
        String script = callExecWithReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", Script.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "exec", operation.getMethodName());
    }

    @Test
    public void testCompileFunction() throws IOException {
        String script = callCompileFunction();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", Script.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "exec", operation.getMethodName());
    }

    @Test
    public void testFunctionCall(){
        String script = callFunctionCall();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", Script.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "exec", operation.getMethodName());
    }

    @Test
    public void testFunctionCallWithReader() throws IOException {
        String script = callFunctionCallWithReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", script, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", Script.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "exec", operation.getMethodName());
    }
}
