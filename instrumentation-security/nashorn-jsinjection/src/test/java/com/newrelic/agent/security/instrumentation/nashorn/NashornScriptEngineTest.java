package com.newrelic.agent.security.instrumentation.nashorn;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.JSInjectionOperation;
import com.newrelic.security.test.marker.Java15IncompatibleTest;
import com.newrelic.security.test.marker.Java16IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.security.test.marker.Java18IncompatibleTest;
import com.newrelic.security.test.marker.Java19IncompatibleTest;
import jdk.nashorn.api.scripting.NashornScriptEngine;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import javax.script.CompiledScript;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URISyntaxException;
import java.util.List;

@Category({ Java15IncompatibleTest.class, Java16IncompatibleTest.class, Java17IncompatibleTest.class, Java18IncompatibleTest.class, Java19IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "jdk.nashorn")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class NashornScriptEngineTest {
    @Trace
    private static void callEngineEval(String code) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("Nashorn");
        engine.eval(code);
    }

    @Trace
    private static void callEngineEvalReader() throws ScriptException, FileNotFoundException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("Nashorn");
        engine.eval(new FileReader("src/test/resources/script.js"));
    }

    @Trace
    private static void callEngineCompile(String code) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("Nashorn");
        CompiledScript script = ((javax.script.Compilable) engine).compile(code);
        script.eval();
    }

    @Trace
    private static void callEngineCompileWithReader() throws ScriptException, FileNotFoundException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("Nashorn");
        CompiledScript script = ((javax.script.Compilable) engine).compile(new FileReader("src/test/resources/script.js"));
        script.eval();
    }

    @Trace
    private static void callEngineCompileAndEval(String[] code) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("Nashorn");
        CompiledScript script = ((javax.script.Compilable) engine).compile(code[0]);
        script.eval();
        Object result = engine.eval(code[1]);
        System.out.println("Function call result: " + result);
    }

    @Trace
    private static void callEngineCompileAndEvalWithReader(String[] code) throws ScriptException, FileNotFoundException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("Nashorn");
        CompiledScript script = ((javax.script.Compilable) engine).compile(new FileReader("src/test/resources/script.js"));
        script.eval();
        engine.eval(code[1]);
    }

    @Trace
    private static void callEngineInvokeFunction(String[] code) throws ScriptException, NoSuchMethodException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("Nashorn");
        CompiledScript script = ((javax.script.Compilable) engine).compile(code[0]);
        script.eval();
        Invocable invocable = (Invocable) engine;
        invocable.invokeFunction("fun1", "Spiderman");
    }

    @Trace
    private static void callEngineInvokeFunctionWithReader() throws ScriptException, FileNotFoundException, NoSuchMethodException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("Nashorn");
        engine.eval(new FileReader("src/test/resources/script.js"));
        Invocable invocable = (Invocable) engine;
        invocable.invokeFunction("fun1", "Peter Parker");
    }

    @Trace
    private static void callEngineInvokeMethod(String[] code) throws ScriptException, NoSuchMethodException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("Nashorn");
        Invocable invocable = (Invocable) engine;
        engine.eval(code[0]);
        Object myCode = engine.get("myCode");
        invocable.invokeMethod(myCode, "show", "Pokemon");
    }

    @Trace
    private static void callEngineInvokeMethodWithReader() throws ScriptException, FileNotFoundException, NoSuchMethodException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("Nashorn");
        engine.eval(new FileReader("src/test/resources/script_1.js"));
        Invocable invocable = (Invocable) engine;
        Object myCode = engine.get("myCode");
        invocable.invokeMethod(myCode, "show", "Ash");
    }

    @Test
    public void testEval() throws ScriptException {
        String code = "print('Hello, Monu!')";
        callEngineEval(code);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", code, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
    }

    @Test
    public void testEvalWithReader() throws ScriptException, FileNotFoundException {
        String code = "var fun1 = function(name) { print('Hi, ' + name); };";
        callEngineEvalReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", code, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
    }

    @Test
    public void testCompile() throws ScriptException {
        String code = "print('Hello, Nashorn!')";
        callEngineCompile(code);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", code, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
    }

    @Test
    public void testCompileWithReader() throws ScriptException, FileNotFoundException {
        String code = "var fun1 = function(name) { print('Hi, ' + name); };";
        callEngineCompileWithReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        JSInjectionOperation operation = (JSInjectionOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", code, operation.getJavaScriptCode());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
    }

    @Test
    public void testCompileAndEval() throws ScriptException {
        String[] code = { "function send(a) { return a; }", "send(\"monu\")" };
        callEngineCompileAndEval(code);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Not all the expected operations were detected.", 2, operations.size());
        for (int i = 0; i < operations.size(); i++) {
            JSInjectionOperation operation = (JSInjectionOperation) operations.get(i);
            Assert.assertEquals("Invalid executed parameters.", code[i], operation.getJavaScriptCode());
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
            Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
            Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
        }
    }

    @Test
    public void testCompileAndEvalWithReader() throws ScriptException, FileNotFoundException {
        String[] code = { "var fun1 = function(name) { print('Hi, ' + name); };", "fun1(\"Hero\")" };
        callEngineCompileAndEvalWithReader(code);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Not all the expected operations were detected.", 2, operations.size());
        for (int i = 0; i < operations.size(); i++) {
            JSInjectionOperation operation = (JSInjectionOperation) operations.get(i);
            Assert.assertEquals("Invalid executed parameters.", code[i], operation.getJavaScriptCode());
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
            Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
            Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
        }
    }

    @Test
    public void testInvokeFunction() throws ScriptException, FileNotFoundException, NoSuchMethodException, URISyntaxException {
        String[] code = { "var fun1 = function(name) { print('Hi, ' + name); };", "fun1(\"Spiderman\")" };
        callEngineInvokeFunction(code);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        // FIXME: after invokeFunction method instrumentation
        Assert.assertEquals("Not all the expected operations were detected.", 1, operations.size());
        for (int i = 0; i < operations.size(); i++) {
            JSInjectionOperation operation = (JSInjectionOperation) operations.get(i);
            Assert.assertEquals("Invalid executed parameters.", code[i], operation.getJavaScriptCode());
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
            Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
            Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
        }
    }

    @Test
    public void testInvokeFunctionWithReader() throws ScriptException, FileNotFoundException, NoSuchMethodException, URISyntaxException {
        String[] code = { "var fun1 = function(name) { print('Hi, ' + name); };", "fun1(\"Peter Parker\")" };
        callEngineInvokeFunctionWithReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        // FIXME: after invokeFunction method instrumentation
        Assert.assertEquals("Not all the expected operations were detected.", 1, operations.size());
        for (int i = 0; i < operations.size(); i++) {
            JSInjectionOperation operation = (JSInjectionOperation) operations.get(i);
            Assert.assertEquals("Invalid executed parameters.", code[i], operation.getJavaScriptCode());
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
            Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
            Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
        }
    }

    @Test
    public void testInvokeMethod() throws ScriptException, FileNotFoundException, NoSuchMethodException, URISyntaxException {
        String[] code = { "var myCode = new Object(); myCode.show = function(name) { print('Hi, ' + name); };", "show(\"Pokemon\")" };
        callEngineInvokeMethod(code);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        // FIXME: after invokeMethod method instrumentation
        Assert.assertEquals("Not all the expected operations were detected.", 1, operations.size());
        for (int i = 0; i < operations.size(); i++) {
            JSInjectionOperation operation = (JSInjectionOperation) operations.get(i);
            Assert.assertEquals("Invalid executed parameters.", code[i], operation.getJavaScriptCode());
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
            Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
            Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
        }
    }

    @Test
    public void testInvokeMethodWithReader() throws ScriptException, FileNotFoundException, NoSuchMethodException, URISyntaxException {
        String[] code = { "var myCode = new Object(); myCode.show = function(name) { print('Hi, ' + name); };", "show(\"Ash\")" };
        callEngineInvokeMethodWithReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        // FIXME: after invokeMethod method instrumentation
        Assert.assertEquals("Not all the expected operations were detected.", 1, operations.size());
        for (int i = 0; i < operations.size(); i++) {
            JSInjectionOperation operation = (JSInjectionOperation) operations.get(i);
            Assert.assertEquals("Invalid executed parameters.", code[i], operation.getJavaScriptCode());
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.JAVASCRIPT_INJECTION, operation.getCaseType());
            Assert.assertEquals("Invalid executed class name.", NashornScriptEngine.class.getName(), operation.getClassName());
            Assert.assertEquals("Invalid executed method name.", "evalImpl", operation.getMethodName());
        }
    }
}
