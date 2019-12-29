package com.k2cybersecurity.instrumentator;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Hooks {

    public static Map<String, List<String>> NAME_BASED_HOOKS = new HashMap<>();

    public static Map<String, List<String>> TYPE_BASED_HOOKS = new HashMap<>();

    public static Map<String, String> DECORATOR_ENTRY = new HashMap<>();

    static {
        // HTTP request hooks
        TYPE_BASED_HOOKS.put("javax.servlet.GenericServlet", Arrays.asList("service"));
        TYPE_BASED_HOOKS.put("javax.servlet.ServletInputStream", Arrays.asList("read"));

        // Decorators
        DECORATOR_ENTRY.put("javax.servlet.GenericServlet.service", "com.k2cybersecurity.instrumentator.decorators.httpservice");
        DECORATOR_ENTRY.put("javax.servlet.ServletInputStream.read", "com.k2cybersecurity.instrumentator.decorators.servletinputstream");
    }
}
