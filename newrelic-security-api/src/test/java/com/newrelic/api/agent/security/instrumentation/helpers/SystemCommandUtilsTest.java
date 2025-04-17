package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

public class SystemCommandUtilsTest {

    @Test
    public void isShellScriptExecutionTest() {
        List<String> shellScripts = new ArrayList<>();
        Assertions.assertEquals(shellScripts, SystemCommandUtils.isShellScriptExecution("bash echo \"hello\""));
        Assertions.assertEquals(shellScripts, SystemCommandUtils.isShellScriptExecution("bash ls; echo $var"));
    }

    @Test
    public void getAbsoluteShellScriptsTest() {
        List<String> shellScripts = new ArrayList<>();
        Assertions.assertEquals(shellScripts, SystemCommandUtils.getAbsoluteShellScripts(Collections.singletonList("/tmp/test.sh")));
        Assertions.assertEquals(shellScripts, SystemCommandUtils.isShellScriptExecution("/tmp"));
    }

    @Test
    public void scriptContentTest() throws IOException {
        String content = "bash echo hello\n";
        File file = new File(String.format("/tmp/%s_file.sh", UUID.randomUUID()));
        file.createNewFile();
        file.deleteOnExit();
        if (file.exists()) {
            Files.write(Paths.get(file.toURI()), content.getBytes());
        }
        ForkExecOperation operation = new ForkExecOperation("", new HashMap<>(), "", "");
        SystemCommandUtils.scriptContent(Collections.singletonList(file.getAbsolutePath()), operation);
        Assertions.assertFalse(operation.getScriptContent().isEmpty());
        Assertions.assertTrue(operation.getScriptContent().containsKey(file.getName()));
        Assertions.assertEquals(content, operation.getScriptContent().get(file.getName()));
    }

}
