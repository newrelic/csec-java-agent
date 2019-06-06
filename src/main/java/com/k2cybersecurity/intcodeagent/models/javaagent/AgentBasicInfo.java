package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.util.Properties;

import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;

// TODO: Auto-generated Javadoc
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

	private static Properties props;

	static {
		props = new Properties();
		try {
			props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(IAgentConstants.K2_JAVAAGENT_PROPERTIES));
		} catch (Exception e) {
			System.err.println("Could not load properties");
		}
	}


	/**
	 * Instantiates a new agent basic info according to the source class object.
	 */
	public AgentBasicInfo() {
		setVersion(props.getProperty(IAgentConstants.K2_JAVAAGENT_VERSION));
		setK2JAToolId(props.getProperty(IAgentConstants.K2_JAVAAGENT_TOOL_ID));
		if (this instanceof  ApplicationInfoBean) {
			setJsonName(props.getProperty(IAgentConstants.K2_JAVAAGENT_JSONNAME_APPLICATIONINFOBEAN));
		} else if (this instanceof JavaAgentEventBean) {
			setJsonName(props.getProperty(IAgentConstants.K2_JAVAAGENT_JSONNAME_INTCODERESULTBEAN));
		} else if(this instanceof JavaAgentJarPathBean){
			setJsonName(props.getProperty(IAgentConstants.K2_JAVAAGENT_JSONNAME_JARPATHBEAN));
		} else if(this instanceof JavaAgentDynamicPathBean){
			setJsonName(props.getProperty(IAgentConstants.K2_JAVAAGENT_JSONNAME_DYNAMICJARPATHBEAN));
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

}
