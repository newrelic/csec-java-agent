package com.k2cybersecurity.intcodeagent.models.javaagent;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.properties.K2JAVersionInfo;


/**
 * The Class AgentBasicInfo.
 */
public class AgentBasicInfo {

	/**  Tool id for JavaAgent. */
	private String k2JAToolId;

	/** The Json name. */
	private String jsonName;

	/** Json version number. */
	private String version;

	private static Logger logger;

	/**
	 * Instantiates a new agent basic info according to the source class object.
	 */
	public AgentBasicInfo() {
		setVersion(K2JAVersionInfo.javaAgentVersion);
		setK2JAToolId(K2JAVersionInfo.buildId);
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
		}
	}

	/**
	 * Gets the k2 JavaAagent tool id.
	 *
	 * @return the k2 JavaAagent tool id.
	 */
	public String getK2JAToolId() {
		return k2JAToolId;
	}

	/**
	 * Sets the k2 JavaAagent tool id.
	 *
	 * @param k2jaToolId the new k2 JavaAagent tool id.
	 */
	public void setK2JAToolId(String k2jaToolId) {
		k2JAToolId = k2jaToolId;
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
	
	public static void setLogger() {
		AgentBasicInfo.logger = Logger.getLogger(AgentBasicInfo.class.getName());
	}
	
}
