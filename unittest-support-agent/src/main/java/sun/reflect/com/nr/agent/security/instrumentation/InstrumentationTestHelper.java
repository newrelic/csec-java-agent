package sun.reflect.com.nr.agent.security.instrumentation;

import java.lang.instrument.Instrumentation;

public class InstrumentationTestHelper {

    public static Instrumentation instrumentation;

    public static void premain(String agentArgs, Instrumentation inst) {
        instrumentation = inst;
        System.out.println("NR Instrumentation helper agent init complete for classloader " + InstrumentationTestHelper.class.getClassLoader());
    }

}
