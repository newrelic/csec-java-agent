package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SystemCommandUtils {

    private static final Pattern commandShellRegex = Pattern.compile("(\\S+\\.sh(?!\\S))");

    public static List<String> isShellScriptExecution(String command) {
        Matcher matcher = commandShellRegex.matcher(command);

        List<String> shellScripts = new ArrayList<>();
        while (matcher.find()){
            shellScripts.add(matcher.group().trim());
        }
        return shellScripts;
    }

    public static List<String> getAbsoluteShellScripts(List<String> shellScripts) {
        List<String> absoluteSrcipts = new ArrayList<>();

        for (String shellScript : shellScripts) {
            File script = new File(shellScript);
            if(script.isFile()){
                absoluteSrcipts.add(script.getAbsolutePath());
            }
        }

        return absoluteSrcipts;
    }

    public static void scriptContent(List<String> absolutePaths, ForkExecOperation operation) {
        for (String absolutePath : absolutePaths) {
            try {
                BufferedReader reader = new BufferedReader(new FileReader(absolutePath));
                StringBuilder content = new StringBuilder();
                String line = reader.readLine();
                while(line != null) {
                    content.append(line);
                    content.append(StringUtils.LF);
                    line = reader.readLine();
                }
                operation.getScriptContent().put(new File(absolutePath).getName(), content.toString());
            } catch (IOException e) {
            }
        }
    }
}
