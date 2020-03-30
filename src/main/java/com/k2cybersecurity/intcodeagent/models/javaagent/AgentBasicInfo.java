package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.properties.K2JAVersionInfo;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;


/**
 * The Class AgentBasicInfo.
 */
public class AgentBasicInfo {

	private static final String SCAN_COMPONENT_DATA = "scanComponentData";

	/**  Tool id for Language Agent. */
	private String k2LAToolId;

	/** The Json name. */
	private String jsonName;

	/** Json version number. */
	private String version;
	
	private final String collectorType = "JAVA";

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	/**
	 * Instantiates a new agent basic info according to the source class object.
	 */
	public AgentBasicInfo() {
		setVersion(K2JAVersionInfo.javaAgentVersion);
		setK2LAToolId(K2JAVersionInfo.buildId);
		if (this instanceof  ApplicationInfoBean) {
			setJsonName(JSON_NAME_APPLICATION_INFO_BEAN);
		} else if (this instanceof JavaAgentEventBean) {
			setJsonName(JSON_NAME_INTCODE_RESULT_BEAN);
		} else if(this instanceof JAHealthCheck) {
			setJsonName(JSON_NAME_HEALTHCHECK);
		} else if(this instanceof ShutDownEvent) {
			setJsonName(JSON_NAME_SHUTDOWN);
		} else if (this instanceof JavaAgentDynamicPathBean) {
			setJsonName(JSON_NAME_DYNAMICJARPATH_BEAN);
		} else if( this instanceof ScanComponentData) {
			setJsonName(SCAN_COMPONENT_DATA);
		}
	}

	/**
	 * Gets the Language Agent tool id.
	 *
	 * @return the Language Agent tool id.
	 */
	public String getK2LAToolId() {
		return k2LAToolId;
	}

	/**
	 * Sets the Language Agent tool id.
	 *
	 * @param k2jaToolId Language Agent tool id.
	 */
	public void setK2LAToolId(String k2jaToolId) {
		k2LAToolId = k2jaToolId;
	}

	/**
	 * Gets the jsonName.
	 *
	 * @return the jsonName
	 */
	public String getJsonName() {
		return jsonName;
	}

	/**
	 * Sets the jsonName.
	 *
	 * @param jsonName the new jsonName
	 */
	public void setJsonName(String jsonName) {
		this.jsonName = jsonName;
	}

	/**
	 * Gets the version.
	 *
	 * @return the version
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Sets the version.
	 *
	 * @param version the new version
	 */
	public void setVersion(String version) {
		this.version = version;
	}
	

	/**
	 * @return the collectorType
	 */
	public String getCollectorType() {
		return collectorType;
	}
	
}
