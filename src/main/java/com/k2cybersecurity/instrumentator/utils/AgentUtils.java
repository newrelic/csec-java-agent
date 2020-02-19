package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerableAPI;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AgentUtils {

	public Set<Pair<String, ClassLoader>> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<Pair<String, ClassLoader>> transformedClasses;

	private Map<String, EventResponse> eventResponseSet;

	private Map<String, VulnerableAPI> vulnerableAPIMap;

	private static AgentUtils instance;

	private AgentUtils() {
		transformedClasses = new HashSet<>();
		eventResponseSet = new ConcurrentHashMap<>();
		vulnerableAPIMap = new ConcurrentHashMap<>();
	}

	public static AgentUtils getInstance() {
		if (instance == null) {
			instance = new AgentUtils();
		}
		return instance;
	}

	public void clearTransformedClassSet() {
		transformedClasses.clear();
	}

	public Map<String, EventResponse> getEventResponseSet() {
		return eventResponseSet;
	}

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public Map<String, VulnerableAPI> getVulnerableAPIMap() {
		return vulnerableAPIMap;
	}

	public VulnerableAPI isVulnerableAPI(JavaAgentEventBean event){
		VulnerableAPI vulnerableAPI = new VulnerableAPI(event.getSourceMethod(),
				event.getUserFileName(),
				event.getUserMethodName(),
				event.getLineNumber()
				);
		return vulnerableAPIMap.get(vulnerableAPI.getId());
	}
}
