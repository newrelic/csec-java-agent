package com.k2cybersecurity.instrumentator.custom;

public class ClassloaderAdjustments {

	public static final String K2_BOOTSTAP_LOADED_PACKAGE_NAME = "sun.reflect.com.k2cybersecurity";

	public static void jbossSpecificAdjustments(){
		System.out.println("Implementing JBoss Classloader adjustments");
		String cur = System.getProperty("jboss.modules.system.pkgs");
		if (cur == null) {
			System.setProperty("jboss.modules.system.pkgs", K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		} else if (!cur.contains(K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
			System.setProperty("jboss.modules.system.pkgs", cur + "," + K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		}
	}

	//
	// TODO: Need to check : https://github.com/DataDog/dd-trace-java/blob/master/dd-java-agent/instrumentation/tomcat-classloading
	//
	public static void tomcatSpecificAdjustments(){
		String cur = System.getProperty("jboss.modules.system.pkgs");
		if (cur == null) {
			System.setProperty("jboss.modules.system.pkgs", K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		} else if (!cur.contains(K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
			System.setProperty("jboss.modules.system.pkgs", cur + "," + K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		}
	}

	public static void osgiSpecificAdjustments(){
		System.out.println("Implementing OSGi Classloader adjustments");
		String cur = System.getProperty("org.osgi.framework.bootdelegation");
		if (cur == null) {
			System.setProperty("org.osgi.framework.bootdelegation", K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		} else if (!cur.contains(K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
			System.setProperty("org.osgi.framework.bootdelegation", cur + "," + K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		}
	}
}
