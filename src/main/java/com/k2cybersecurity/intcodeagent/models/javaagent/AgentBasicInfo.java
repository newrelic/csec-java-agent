package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.CustomerInfo;
import com.k2cybersecurity.intcodeagent.properties.K2JAVersionInfo;
import org.apache.commons.lang3.StringUtils;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;


/**
 * The Class AgentBasicInfo.
 */
public class AgentBasicInfo {

	private static final String SCAN_COMPONENT_DATA = "scanComponentData";

	/**  Tool id for Language Agent. */
	private String collectorVersion;

	/**
	 * The Json name.
	 */
	private String jsonName;

	/**
	 * Json version number.
	 */
	private String jsonVersion;

	private final String collectorType = "JAVA";

	private final String language = "Java";

	private final String framework = StringUtils.EMPTY;

	private String nodeId;

	private Integer customerId;

	/**
	 * Instantiates a new agent basic info according to the source class object.
	 */
	public AgentBasicInfo() {
		setJsonVersion(K2JAVersionInfo.jsonVersion);
		setCollectorVersion(K2JAVersionInfo.collectorVersion);
		setNodeId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
		setCustomerId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getCustomerId());
		if (this instanceof ApplicationInfoBean) {
			setJsonName(JSON_NAME_APPLICATION_INFO_BEAN);
		} else if (this instanceof JavaAgentEventBean) {
			setJsonName(JSON_NAME_INTCODE_RESULT_BEAN);
		} else if(this instanceof JAHealthCheck) {
			setJsonName(JSON_NAME_HEALTHCHECK);
		} else if(this instanceof ShutDownEvent) {
			setJsonName(JSON_NAME_SHUTDOWN);
		} else if (this instanceof JavaAgentDynamicPathBean) {
			setJsonName(JSON_NAME_DYNAMICJARPATH_BEAN);
        } else if (this instanceof ScanComponentData) {
            setJsonName(SCAN_COMPONENT_DATA);
        } else if (this instanceof FuzzFailEvent) {
            setJsonName(JSON_NAME_FUZZ_FAIL);
        } else if (this instanceof HttpConnectionStat) {
            setJsonName(JSON_NAME_HTTP_CONNECTION_STAT);
        }
	}

	/**
	 * Gets the Language Agent tool id.
	 *
	 * @return the Language Agent tool id.
	 */
	public String getCollectorVersion() {
		return collectorVersion;
	}

	/**
	 * Sets the Language Agent tool id.
	 *
	 * @param k2jaToolId Language Agent tool id.
	 */
	public void setCollectorVersion(String k2jaToolId) {
		collectorVersion = k2jaToolId;
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
	public String getJsonVersion() {
		return jsonVersion;
	}

	/**
	 * Sets the version.
	 *
	 * @param jsonVersion the new version
	 */
	public void setJsonVersion(String jsonVersion) {
		this.jsonVersion = jsonVersion;
	}

	public String getLanguage() {
		return language;
	}

	public String getFramework() {
		return framework;
	}

	/**
	 * @return the collectorType
	 */
	public String getCollectorType() {
		return collectorType;
	}

	public String getNodeId() {
		return nodeId;
	}

	public void setNodeId(String nodeId) {
		this.nodeId = nodeId;
	}

	public Integer getCustomerId() {
		return customerId;
	}

	public void setCustomerId(Integer customerId) {
		this.customerId = customerId;
	}
}
