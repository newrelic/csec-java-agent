package com.k2cybersecurity.instrumentator.decorators.jbossadjustment;

import java.util.Arrays;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args, String exectionId) {
        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
        jbossSpecificAdjustments();
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args, Object returnVal, String exectionId) {
        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
        jbossSpecificAdjustments();

    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args, Throwable error, String exectionId) throws Throwable {
        System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - error : " + error + " - eid : " + exectionId);
        jbossSpecificAdjustments();
    }

    public static void jbossSpecificAdjustments(){
        String cur = System.getProperty("jboss.modules.system.pkgs");
        if (cur == null) {
            System.setProperty("jboss.modules.system.pkgs", "sun.reflect.com.k2cybersecurity");
        } else if (!cur.contains("sun.reflect.com.k2cybersecurity")) {
            System.setProperty("jboss.modules.system.pkgs", cur + "," + "sun.reflect.com.k2cybersecurity");
        }
    }
}
