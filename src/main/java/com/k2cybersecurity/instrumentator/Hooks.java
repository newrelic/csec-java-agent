package com.k2cybersecurity.instrumentator;

import java.util.*;

public class Hooks {

    public static Map<String, List<String>> NAME_BASED_HOOKS = new HashMap<>();

    public static Map<String, List<String>> TYPE_BASED_HOOKS = new HashMap<>();

    public static Map<String, String> DECORATOR_ENTRY = new HashMap<>();

    static {
//        NAME_BASED_HOOKS.put("ml.harshitandro.Testing", Arrays.asList("test", null));

        // Custom Test Hook
//        TYPE_BASED_HOOKS.put("ml.harshitandro.Test", Arrays.asList("test"));

        // HTTP request hooks
        TYPE_BASED_HOOKS.put("javax.servlet.GenericServlet", Arrays.asList("service"));

        // Decorators
        DECORATOR_ENTRY.put("javax.servlet.GenericServlet.service", "com.k2cybersecurity.instrumentator.decorators.httpservice");

    }
}
