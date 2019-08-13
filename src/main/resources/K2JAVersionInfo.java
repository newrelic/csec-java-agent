package com.k2cybersecurity.intcodeagent.properties;
public interface K2JAVersionInfo {
	String buildId = "${buildId}";
	String buildTime = "${buildTime}";
	String commitId = "${commitId}";
	String javaAgentVersion = "${k2JavaAgentVersion}";
}
