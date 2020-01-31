package com.k2cybersecurity.instrumentator.utils;

import java.util.HashSet;
import java.util.Set;

public class AgentUtils {

	public Set<String> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<String> transformedClasses;

	private static AgentUtils instance;


	private AgentUtils(){
		transformedClasses = new HashSet<>();
	}

	public static AgentUtils getInstance() {
		if(instance == null) {
			instance = new AgentUtils();
		}
		return instance;
	}

	public void clearTransformedClassSet(){
		transformedClasses.clear();
	}

}
