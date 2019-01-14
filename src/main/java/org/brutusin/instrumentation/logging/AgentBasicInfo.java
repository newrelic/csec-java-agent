package org.brutusin.instrumentation.logging;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

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

	{
		props = new Properties();
		InputStream in = null;
		try {
			in = AgentBasicInfo.class.getResourceAsStream("/application.properties");
			props.load(in);
		} catch (IOException e) {
			throw new RuntimeException(e.getMessage());
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					throw new RuntimeException(e.getMessage());
				}
			}
		}

	}


	/**
	 * Instantiates a new agent basic info according to the source class object.
	 */
	public AgentBasicInfo() {
		setVersion(props.getProperty("k2.javaagent.version"));
		if (this instanceof  ApplicationInfoBean) {
			setJsonName(props.getProperty("k2.javaagent.jsonname.applicationinfobean"));
		} else if (this instanceof IntCodeResultBean) {
			setJsonName(props.getProperty("k2.javaagent.jsonname.intcoderesultbean"));
		} else if(this instanceof JarPathBean){
			setJsonName(props.getProperty("k2.javaagent.jsonname.jarpathbean"));
		} else if(this instanceof DynamicJarPathBean){
			setJsonName(props.getProperty("k2.javaagent.jsonname.dynamicjarpathbean"));
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
