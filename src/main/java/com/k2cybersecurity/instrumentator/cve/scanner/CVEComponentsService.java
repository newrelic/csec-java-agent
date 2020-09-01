package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationScanComponentData;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEComponent;
import com.k2cybersecurity.intcodeagent.models.javaagent.ScanComponentData;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class CVEComponentsService {

	private static final String JAR_EXTENSION = ".jar";

	private static final String JAR_EXT = "jar";
	
	private static Set<CVEComponent> envCveComponents = new HashSet<>();
	
	static {
		envCveComponents = getCVEComponents(getLibPaths());
	}

	public static ScanComponentData getAllComponents(DeployedApplication deployedApplication) {
		Set<String> appJarPaths = getAllJarsFromApp(deployedApplication.getDeployedPath());
		ScanComponentData scanComponentData = new ScanComponentData(K2Instrumentator.APPLICATION_UUID);
		ApplicationScanComponentData applicationScanComponentData = new ApplicationScanComponentData(
				deployedApplication.getAppName(), deployedApplication.getSha256());
		applicationScanComponentData.setComponents(getCVEComponents(appJarPaths));
		envCveComponents.removeAll(applicationScanComponentData.getComponents());
		scanComponentData.setEnvComponents(envCveComponents);
		scanComponentData.setDeployedApplications(Collections.singleton(applicationScanComponentData));
		return scanComponentData;
	}

	private static Set<CVEComponent> getCVEComponents(Set<String> libPaths) {
		Set<CVEComponent> cveComponents = new HashSet();

		for (String path : libPaths) {
			File file = new File(path);
			if (file.length() != 0) {
				cveComponents.add(new CVEComponent(file.getName(), HashGenerator.getChecksum(file)));
			}
		}

		return cveComponents;
	}

	private static Set<String> getAllJarsFromApp(String deployedPath) {
		Set<String> jars = new HashSet<>();
		File app = new File(deployedPath);
		if (app.isFile()) {
			jars.add(deployedPath);
		} else if (app.isDirectory()) {
			FileUtils.listFiles(app, new String[] { JAR_EXT }, true)
					.forEach(jarFile -> jars.add(jarFile.getAbsolutePath()));
		}
		return jars;
	}

	public static Set<String> getLibPaths() {
		Set<String> libPaths = new HashSet<>();
		if (!K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath().isEmpty()) {
			for (String path : K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath()) {
				if (StringUtils.endsWith(path, JAR_EXTENSION) && !StringUtils.endsWithIgnoreCase(path, "K2-JavaAgent-1.0.0-jar-with-dependencies.jar")) {
					libPaths.add(path);
				} else if (new File(path).isDirectory()) {
					FileUtils.listFiles(new File(path), new String[]{JAR_EXT}, true)
							.forEach(jarFile -> libPaths.add(jarFile.getAbsolutePath()));
				}
			}
		}
		return libPaths;
	}

}
