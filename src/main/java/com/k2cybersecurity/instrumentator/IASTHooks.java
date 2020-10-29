package com.k2cybersecurity.instrumentator;

import java.util.*;

public class IASTHooks {

    public static Map<String, List<String>> NAME_BASED_HOOKS = new HashMap<>();

    public static Map<String, List<String>> TYPE_BASED_HOOKS = new HashMap<>();

    public static Set<String> ANNOTATION_BASED_HOOKS = new HashSet<>();

    public static Map<String, String> DECORATOR_ENTRY = new HashMap<>();

    static {

        /**
         * ------------------------------------ Hooks
         * ------------------------------------------------
         **/

        // trust boundary hooks
        TYPE_BASED_HOOKS.put("javax.servlet.http.HttpSession", Arrays.asList("setAttribute", "putValue"));
        DECORATOR_ENTRY.put("javax.servlet.http.HttpSession.setAttribute",
                "com.k2cybersecurity.instrumentator.decorators.trustboundary");
        DECORATOR_ENTRY.put("javax.servlet.http.HttpSession.putValue",
                "com.k2cybersecurity.instrumentator.decorators.trustboundary");


        // Secure Cookie
        TYPE_BASED_HOOKS.put("javax.servlet.http.HttpServletResponse", Collections.singletonList("addCookie"));
        DECORATOR_ENTRY.put("javax.servlet.http.HttpServletResponse.addCookie",
                "com.k2cybersecurity.instrumentator.decorators.securecookie");


        // Weak Random
        NAME_BASED_HOOKS.put("java.util.Random", Arrays.asList(new String[]{"nextBytes", "nextInt", "nextLong",
                "nextBoolean", "nextFloat", "nextDouble", "nextGaussian"}));
        NAME_BASED_HOOKS.put("java.lang.Math", Collections.singletonList("random"));
        DECORATOR_ENTRY.put("java.util.Random.nextBytes", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.util.Random.nextInt", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.util.Random.nextLong", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.util.Random.nextBoolean", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.util.Random.nextFloat", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.util.Random.nextDouble", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.util.Random.nextGaussian",
                "com.k2cybersecurity.instrumentator.decorators.weakrandom");
        DECORATOR_ENTRY.put("java.lang.Math.random", "com.k2cybersecurity.instrumentator.decorators.weakrandom");


        // Strong random
        NAME_BASED_HOOKS.put("java.security.SecureRandom", Arrays.asList(new String[]{"nextBytes", "nextInt",
                "nextLong", "nextBoolean", "nextFloat", "nextDouble", "nextGaussian"}));
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextBytes",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextInt",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextLong",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextBoolean",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextFloat",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextDouble",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");
        DECORATOR_ENTRY.put("java.security.SecureRandom.nextGaussian",
                "com.k2cybersecurity.instrumentator.decorators.strongrandom");


        // CRYPTO
        NAME_BASED_HOOKS.put("javax.crypto.Cipher", Collections.singletonList("getInstance"));
        NAME_BASED_HOOKS.put("javax.crypto.KeyGenerator", Collections.singletonList("getInstance"));
        NAME_BASED_HOOKS.put("java.security.KeyPairGenerator", Collections.singletonList("getInstance"));
        DECORATOR_ENTRY.put("javax.crypto.Cipher.getInstance", "com.k2cybersecurity.instrumentator.decorators.crypto");
        DECORATOR_ENTRY.put("javax.crypto.KeyGenerator.getInstance",
                "com.k2cybersecurity.instrumentator.decorators.crypto");
        DECORATOR_ENTRY.put("java.security.KeyPairGenerator.getInstance",
                "com.k2cybersecurity.instrumentator.decorators.crypto");


        // HASH
        NAME_BASED_HOOKS.put("java.security.MessageDigest", Collections.singletonList("getInstance"));
        DECORATOR_ENTRY.put("java.security.MessageDigest.getInstance",
                "com.k2cybersecurity.instrumentator.decorators.hash");

        // File Exist
        TYPE_BASED_HOOKS.put("java.io.FileSystem", Collections.singletonList("getBooleanAttributes"));
        DECORATOR_ENTRY.put("java.io.FileSystem.getBooleanAttributes",
                "com.k2cybersecurity.instrumentator.decorators.fileaccess");

    }
}
