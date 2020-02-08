package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashSet;
import java.util.Set;

public class AgentUtils {

	public Set<Pair<String, ClassLoader>> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<Pair<String, ClassLoader>> transformedClasses;

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

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

}
