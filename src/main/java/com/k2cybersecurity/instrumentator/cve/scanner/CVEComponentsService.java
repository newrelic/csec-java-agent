package com.k2cybersecurity.instrumentator.cve.scanner;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationScanComponentData;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEComponent;
import com.k2cybersecurity.intcodeagent.models.javaagent.ScanComponentData;

public class CVEComponentsService {

	private static final String JAR_EXTENSION = ".jar";

	private static final String JAR_EXT = "jar";

	public static ScanComponentData getAllComponents(DeployedApplication deployedApplication) {
		Set<String> libPaths = getLibPaths();
		Set<String> appJarPaths = getAllJarsFromApp(deployedApplication.getDeployedPath());
		ScanComponentData scanComponentData = new ScanComponentData(K2Instrumentator.APPLICATION_UUID);
		ApplicationScanComponentData applicationScanComponentData = new ApplicationScanComponentData(
				deployedApplication.getAppName(), deployedApplication.getSha256());
		scanComponentData.setEnvComponents(getCVEComponents(libPaths));
		applicationScanComponentData.setComponents(getCVEComponents(appJarPaths));
		scanComponentData.setDeployedApplications(Collections.singletonList(applicationScanComponentData));
		return scanComponentData;
	}

	private static List<CVEComponent> getCVEComponents(Set<String> libPaths) {
		List<CVEComponent> cveComponents = new ArrayList<>();

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
				if (StringUtils.endsWith(path, JAR_EXTENSION)) {
					libPaths.add(path);
				} else if (new File(path).isDirectory()) {
					FileUtils.listFiles(new File(path), new String[] { JAR_EXT }, true)
							.forEach(jarFile -> libPaths.add(jarFile.getAbsolutePath()));
				}
			}
		}
		return libPaths;
	}

}
