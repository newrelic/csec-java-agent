package com.k2cybersecurity.intcodeagent;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Hooks {

    public static Map<String, List<String>> NAME_BASED_HOOKS = new HashMap<>();

    public static Map<String, List<String>> TYPE_BASED_HOOKS = new HashMap<>();

    public static Map<String, String> DECORATOR_ENTRY = new HashMap<>();

    static {
        NAME_BASED_HOOKS.put("ml.harshitandro.Testing", Arrays.asList("test", null));

        // Custom Test Hook
        TYPE_BASED_HOOKS.put("ml.harshitandro.Test", Arrays.asList("test"));

//        DECORATOR_ENTRY.put("ml.harshitandro.TestInterface.testInterfaceMethod", "ml.harshitandro.decorators.custom");
//        DECORATOR_ENTRY.put("ml.harshitandro.App.printWelcome", "ml.harshitandro.decorators.custom");
//        DECORATOR_ENTRY.put("ml.harshitandro.App.null", "ml.harshitandro.decorators.custom");

        DECORATOR_ENTRY.put("ml.harshitandro.Testing.null", "com.k2cybersecurity.intcodeagent.decorators.custom");
        DECORATOR_ENTRY.put("ml.harshitandro.Testing.test", "com.k2cybersecurity.intcodeagent.decorators.custom");
        DECORATOR_ENTRY.put("ml.harshitandro.Test.test", "com.k2cybersecurity.intcodeagent.decorators.custom");




    }
}
