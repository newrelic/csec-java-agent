package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import org.apache.commons.lang3.StringUtils;

public class ClassloaderAdjustments {

	public static final String K2_BOOTSTAP_LOADED_PACKAGE_NAME = "sun.reflect.com.k2cybersecurity";
	public static final String K2_BOOTSTAP_LOADED_PACKAGE_NAME_OSGI = "sun.reflect.com.k2cybersecurity.*";


	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String IMPLEMENTING_J_BOSS_CLASSLOADER_ADJUSTMENTS = "Implementing JBoss Classloader adjustments";

	public static void jbossSpecificAdjustments(){
		logger.log(LogLevel.INFO, IMPLEMENTING_J_BOSS_CLASSLOADER_ADJUSTMENTS, ClassloaderAdjustments.class.getName());
		String cur = System.getProperty("jboss.modules.system.pkgs");
		if (StringUtils.isBlank(cur)) {
			System.setProperty("jboss.modules.system.pkgs", K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		} else if (!StringUtils.containsIgnoreCase(cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
			System.setProperty("jboss.modules.system.pkgs", StringUtils.joinWith(",", cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME));
		}
	}

	//
	// TODO: Need to check : https://github.com/DataDog/dd-trace-java/blob/master/dd-java-agent/instrumentation/tomcat-classloading
	//
	public static void tomcatSpecificAdjustments(){
		String cur = System.getProperty("jboss.modules.system.pkgs");
		if (StringUtils.isBlank(cur)) {
			System.setProperty("jboss.modules.system.pkgs", K2_BOOTSTAP_LOADED_PACKAGE_NAME);
		} else if (!StringUtils.containsIgnoreCase(cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
			System.setProperty("jboss.modules.system.pkgs", StringUtils.joinWith(",", cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME));
		}
	}

	public static void osgiSpecificAdjustments(){
		logger.log(LogLevel.INFO, "Implementing OSGi Classloader adjustments", ClassloaderAdjustments.class.getName());
		String cur = System.getProperty("org.osgi.framework.bootdelegation");
		if (StringUtils.isBlank(cur)) {
			System.setProperty("org.osgi.framework.bootdelegation", K2_BOOTSTAP_LOADED_PACKAGE_NAME_OSGI);
		} else if (!StringUtils.containsIgnoreCase(cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME_OSGI)) {
			System.setProperty("org.osgi.framework.bootdelegation", StringUtils.joinWith(",", cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME_OSGI));
		}
	}
}
