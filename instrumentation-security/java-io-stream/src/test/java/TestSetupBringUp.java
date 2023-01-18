import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;

public class TestSetupBringUp {
    public static void bringUp() {
        try {
            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(FileOutputStream.class, BufferedReader.class, InputStreamReader.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
