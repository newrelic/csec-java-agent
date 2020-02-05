package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.custom.ServletContextInfo;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.logging.ProcessorThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.models.operationalbean.*;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.ObjectInputStream;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class Dispatcher implements Runnable {

	private static final Pattern PATTERN;
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String ERROR = "Error : ";
	public static final char CH_DOT = '.';
	public static final String EMPTY_FILE_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	public static final String DROPPING_APPLICATION_INFO_POSTING_DUE_TO_SIZE_0 = "Dropping application info posting due to size 0 : ";
	public static final String QUESTION_CHAR = "?";
	public static final String SLASH = "/";
	private HttpRequestBean httpRequestBean;
	private AgentMetaData metaData;
	private Object event;
	private StackTraceElement[] trace;
	private VulnerabilityCaseType vulnerabilityCaseType;
	private Map<String, Object> extraInfo;

	static {
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
	}

	public Dispatcher(Object event, VulnerabilityCaseType vulnerabilityCaseType) {
		this.event = event;
		this.vulnerabilityCaseType = vulnerabilityCaseType;
	}

	public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, StackTraceElement[] trace, Object event,
			VulnerabilityCaseType vulnerabilityCaseType) {
		this.httpRequestBean = httpRequestBean;
		this.metaData = metaData;
		this.event = event;
		this.trace = trace;
		this.vulnerabilityCaseType = vulnerabilityCaseType;
		extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());
	}

	public Dispatcher(HttpRequestBean httpRequestBean, StackTraceElement[] trace, VulnerabilityCaseType reflectedXss,
			String sourceString, String exectionId, long startTime) {
		this.httpRequestBean = httpRequestBean;
		this.trace = trace;
		this.vulnerabilityCaseType = reflectedXss;
		this.extraInfo = new HashMap<String, Object>();
		extraInfo.put(SOURCESTRING, sourceString);
		extraInfo.put(EXECUTIONID, exectionId);
		extraInfo.put(STARTTIME, startTime);
		extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());
	}

	public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, StackTraceElement[] trace,
			FileOperationalBean event, FileIntegrityBean fbean, VulnerabilityCaseType vulnerabilityCaseType) {
		this.httpRequestBean = httpRequestBean;
		this.metaData = metaData;
		this.event = event;
		this.trace = trace;
		this.vulnerabilityCaseType = vulnerabilityCaseType;
		this.extraInfo = new HashMap<String, Object>();
		extraInfo.put(FILEINTEGRITYBEAN, fbean);
		extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());
	}

	@Override
	public void run() {
//        printDispatch();
		try {
			if (vulnerabilityCaseType.equals(VulnerabilityCaseType.REFLECTED_XSS)) {
				String xssConstruct = CallbackUtils.checkForReflectedXSS(httpRequestBean);
//				System.out.println("Changes reflected : " + httpRequestBean.getHttpResponseBean().getResponseBody());
				if (StringUtils.isNotBlank(xssConstruct)) {
					JavaAgentEventBean eventBean = prepareEvent(httpRequestBean, metaData, vulnerabilityCaseType);
					JSONArray params = new JSONArray();
					params.add(xssConstruct);
					params.add(httpRequestBean.getHttpResponseBean().getResponseBody());
					eventBean.setParameters(params);
					eventBean.setApplicationUUID(K2Instrumentator.APPLICATION_UUID);
					eventBean.setPid(K2Instrumentator.VMPID);
					// TODO set these
					eventBean.setSourceMethod((String) extraInfo.get(SOURCESTRING));
					eventBean.setId((String) extraInfo.get(EXECUTIONID));
					eventBean.setStartTime((Long) extraInfo.get(STARTTIME));
					eventBean.setBlockingProcessingTime((Long) extraInfo.get(BLOCKING_END_TIME) - eventBean.getStartTime());

					eventBean = getUserInfo(eventBean);
					EventSendPool.getInstance().sendEvent(eventBean);
//					System.out.println("============= Event Start ============");
//					System.out.println(eventBean);
//					System.out.println("============= Event End ============");
				}
				return;
			}
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR , e, Dispatcher.class.getName());
		}

		if (event == null) {
//			System.out.println("------- Invalid event -----------");
			return;
		}

		if (vulnerabilityCaseType.equals(VulnerabilityCaseType.APP_INFO)) {
			DeployedApplication deployedApplication = (DeployedApplication) event;
//			System.out.println("App Info received : " + deployedApplication);
			if(StringUtils.isNotBlank(deployedApplication.getDeployedPath())){
				 File deploymentDir =  Paths.get(deployedApplication.getDeployedPath()).toFile();
				 if(!deployedApplication.isEmbedded() && (!deploymentDir.exists() || deploymentDir.listFiles() == null || deploymentDir.listFiles().length == 0)){
					 File resourceDir =  Paths.get(deployedApplication.getResourcePath()).toFile();
					 if(resourceDir.exists() && resourceDir.listFiles() != null && resourceDir.listFiles().length > 0){
					 	deployedApplication.setDeployedPath(deployedApplication.getResourcePath());
					 }
				 }
			}
			HashGenerator.updateShaAndSize(deployedApplication);

			if(StringUtils.equals(deployedApplication.getSha256(), EMPTY_FILE_SHA)){
				logger.log(LogLevel.ERROR, DROPPING_APPLICATION_INFO_POSTING_DUE_TO_SIZE_0 + deployedApplication , Dispatcher.class.getName());
				return;
			}

//			System.out.println("Processed App Info : " + deployedApplication);
			ApplicationInfoBean applicationInfoBean = K2Instrumentator.APPLICATION_INFO_BEAN;

			applicationInfoBean.getServerInfo().setName(ServletContextInfo.getInstance().getServerInfo());

			if (!applicationInfoBean.getServerInfo().getDeployedApplications().contains(deployedApplication)) {
				applicationInfoBean.getServerInfo().getDeployedApplications().add(deployedApplication);
				EventSendPool.getInstance().sendEvent(applicationInfoBean.toString());
//				System.out.println("============= AppInfo Start ============");
//				System.out.println(applicationInfoBean);
//				System.out.println("============= AppInfo End ============");
			} else {
				//TODO: Handle cases where the port list of a deployed application is lost as the deployed application is already existing.
			}
			return;
		}

		JavaAgentEventBean eventBean = prepareEvent(httpRequestBean, metaData, vulnerabilityCaseType);

		switch (vulnerabilityCaseType) {
		case FILE_OPERATION:
			FileOperationalBean fileOperationalBean = (FileOperationalBean) event;
			eventBean = setGenericProperties(fileOperationalBean, eventBean);
			eventBean = prepareFileEvent(eventBean, fileOperationalBean);
			String URL = StringUtils.substringBefore(httpRequestBean.getUrl(), QUESTION_CHAR);
			if (allowedExtensionFileIO(eventBean.getParameters(), eventBean.getSourceMethod(), URL)) {
//				System.out.println("------- Event ByPass -----------");
				return;
			}
			break;
		case SYSTEM_COMMAND:
			ForkExecOperationalBean operationalBean = (ForkExecOperationalBean) event;
			eventBean = setGenericProperties(operationalBean, eventBean);
			eventBean = prepareSystemCommandEvent(eventBean, operationalBean);
			break;
		case SQL_DB_COMMAND:
			List<SQLOperationalBean> operationalList = (List<SQLOperationalBean>) event;
			if (operationalList.isEmpty()) {
//				System.out.println("------- Invalid event -----------");
				return;
			}
			// eventBean.setEventCategory(getDbName(operationalList.get(0).getClassName()));
			eventBean = setGenericProperties(operationalList.get(0), eventBean);
			eventBean = prepareSQLDbCommandEvent(operationalList, eventBean);
			break;

		case NOSQL_DB_COMMAND:
			NoSQLOperationalBean noSQLOperationalBean = (NoSQLOperationalBean) event;
			eventBean = setGenericProperties(noSQLOperationalBean, eventBean);
			eventBean = prepareNoSQLEvent(eventBean, noSQLOperationalBean);
			break;

		case FILE_INTEGRITY:
			FileIntegrityBean fileIntegrityBean = (FileIntegrityBean) event;
			eventBean = setGenericProperties(fileIntegrityBean, eventBean);
			eventBean = prepareFileIntegrityEvent(eventBean, fileIntegrityBean);
			break;
		case LDAP:
			LDAPOperationalBean ldapOperationalBean = (LDAPOperationalBean) event;
			eventBean = setGenericProperties(ldapOperationalBean, eventBean);
			eventBean = prepareLDAPEvent(eventBean, ldapOperationalBean);
			break;
		case RANDOM:
			RandomOperationalBean randomOperationalBean = (RandomOperationalBean) event;
			eventBean = setGenericProperties(randomOperationalBean, eventBean);
			eventBean = prepareRandomEvent(eventBean, randomOperationalBean);
			break;
		case HTTP_REQUEST:
			SSRFOperationalBean ssrfOperationalBean = (SSRFOperationalBean) event;
			eventBean = setGenericProperties(ssrfOperationalBean, eventBean);
			eventBean = prepareSSRFEvent(eventBean, ssrfOperationalBean);
			break;
		case XPATH:
			XPathOperationalBean xPathOperationalBean = (XPathOperationalBean) event;
			eventBean = setGenericProperties(xPathOperationalBean, eventBean);
			eventBean = prepareXPATHEvent(eventBean, xPathOperationalBean);
			break;
		case SECURE_COOKIE:
			SecureCookieOperationalBean secureCookieOperationalBean = (SecureCookieOperationalBean) event;
			eventBean = setGenericProperties(secureCookieOperationalBean, eventBean);
			eventBean = prepareSecureCookieEvent(eventBean, secureCookieOperationalBean);
			break;
		case TRUSTBOUNDARY:
			TrustBoundaryOperationalBean trustBoundaryOperationalBean = (TrustBoundaryOperationalBean) event;
			eventBean = setGenericProperties(trustBoundaryOperationalBean, eventBean);
			eventBean = prepareTrustBoundaryEvent(eventBean, trustBoundaryOperationalBean);
			break;
		case CRYPTO:
			HashCryptoOperationalBean hashCryptoOperationalBean = (HashCryptoOperationalBean) event;
			eventBean = setGenericProperties(hashCryptoOperationalBean, eventBean);
			eventBean = prepareCryptoEvent(eventBean, hashCryptoOperationalBean);
			break;
		case HASH:
			HashCryptoOperationalBean hashOperationalBean = (HashCryptoOperationalBean) event;
			eventBean = setGenericProperties(hashOperationalBean, eventBean);
			eventBean = prepareHashEvent(eventBean, hashOperationalBean);
			break;
		default:

		}
		if (!VulnerabilityCaseType.FILE_INTEGRITY.equals(vulnerabilityCaseType)) {
			eventBean = processStackTrace(eventBean, vulnerabilityCaseType);
		}
		if (VulnerabilityCaseType.FILE_OPERATION.equals(vulnerabilityCaseType)) {
			createEntryForFileIntegrity((FileOperationalBean) event, eventBean);
		}
		EventSendPool.getInstance().sendEvent(eventBean);
//		System.out.println("============= Event Start ============");
//		System.out.println(eventBean);
//		System.out.println("============= Event End ============");
	}

	private JavaAgentEventBean prepareXPATHEvent(JavaAgentEventBean eventBean,
			XPathOperationalBean xPathOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(xPathOperationalBean.getExpression());
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareHashEvent(JavaAgentEventBean eventBean,
			HashCryptoOperationalBean hashOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(hashOperationalBean.getName());
		if (StringUtils.isNotBlank(hashOperationalBean.getProvider())) {
			params.add(hashOperationalBean.getProvider());
		}
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareCryptoEvent(JavaAgentEventBean eventBean,
			HashCryptoOperationalBean hashCryptoOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(hashCryptoOperationalBean.getName());
		if (StringUtils.isNotBlank(hashCryptoOperationalBean.getProvider())) {
			params.add(hashCryptoOperationalBean.getProvider());
		}
		eventBean.setParameters(params);
		if (eventBean.getSourceMethod().equals(JAVAX_CRYPTO_CIPHER_GETINSTANCE_STRING)
				|| eventBean.getSourceMethod().equals(JAVAX_CRYPTO_CIPHER_GETINSTANCE_STRING_PROVIDER)) {
			eventBean.setEventCategory(CIPHER);
		} else if (eventBean.getSourceMethod().equals(JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING)
				|| eventBean.getSourceMethod().equals(JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING_STRING)
				|| eventBean.getSourceMethod().equals(JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING_PROVIDER)) {
			eventBean.setEventCategory(KEYGENERATOR);
		} else if (eventBean.getSourceMethod().equals(JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING)
				|| eventBean.getSourceMethod().equals(JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING_STRING)
				|| eventBean.getSourceMethod().equals(JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING_PROVIDER)) {
			eventBean.setEventCategory(KEYPAIRGENERATOR);
		}
		return eventBean;
	}

	private JavaAgentEventBean prepareTrustBoundaryEvent(JavaAgentEventBean eventBean,
			TrustBoundaryOperationalBean trustBoundaryOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(trustBoundaryOperationalBean.getKey());
		params.add(trustBoundaryOperationalBean.getValue());
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareRandomEvent(JavaAgentEventBean eventBean,
			RandomOperationalBean randomOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(randomOperationalBean.getClassName());
		eventBean.setEventCategory(randomOperationalBean.getEventCatgory());
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareSecureCookieEvent(JavaAgentEventBean eventBean,
			SecureCookieOperationalBean secureCookieOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(secureCookieOperationalBean.getValue());
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareLDAPEvent(JavaAgentEventBean eventBean, LDAPOperationalBean ldapOperationalBean) {
		JSONArray params = new JSONArray();
		JSONObject object = new JSONObject();
		object.put(NAME, ldapOperationalBean.getName());
		object.put(FILTER, ldapOperationalBean.getFilter());
		params.add(object);
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareFileIntegrityEvent(JavaAgentEventBean eventBean,
			FileIntegrityBean fileIntegrityBean) {
		JSONArray params = new JSONArray();
		params.add(fileIntegrityBean.getFileName());
		eventBean.setParameters(params);
		eventBean.setUserAPIInfo(fileIntegrityBean.getLineNumber(), fileIntegrityBean.getClassName(),
				fileIntegrityBean.getUserMethodName());
		eventBean.setCurrentMethod(fileIntegrityBean.getCurrentMethod());
		return eventBean;
	}

	private void createEntryForFileIntegrity(FileOperationalBean fileOperationalBean, JavaAgentEventBean eventBean) {
		FileIntegrityBean fBean = (FileIntegrityBean) extraInfo.get(FILEINTEGRITYBEAN);
		if (fBean != null) {
			fBean.setBeanValues(eventBean.getSourceMethod(), eventBean.getUserFileName(), eventBean.getUserMethodName(),
					eventBean.getCurrentMethod(), eventBean.getLineNumber());
		}
	}

	private JavaAgentEventBean prepareSQLDbCommandEvent(List<SQLOperationalBean> operationalList,
			JavaAgentEventBean eventBean) {
		JSONArray params = new JSONArray();
		for (SQLOperationalBean operationalBean : operationalList) {
			JSONObject query = new JSONObject();
			query.put(QUERY, operationalBean.getQuery());
			query.put(PARAMETERS, new JSONObject(operationalBean.getParams()));
			params.add(query);
		}
		eventBean.setParameters(params);
		eventBean.setEventCategory(operationalList.get(0).getDbName());
		return eventBean;
	}

	private JavaAgentEventBean prepareSystemCommandEvent(JavaAgentEventBean eventBean,
			ForkExecOperationalBean operationalBean) {
		JSONArray params = new JSONArray();
		params.add(operationalBean.getCommand());
		if (operationalBean.getEnvironment() != null) {
			params.add(new JSONObject(operationalBean.getEnvironment()));
		}
		eventBean.setParameters(params);
		return eventBean;
	}

	private static JavaAgentEventBean prepareFileEvent(JavaAgentEventBean eventBean,
			FileOperationalBean fileOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(fileOperationalBean.getFileName());
		eventBean.setParameters(params);
		return eventBean;
	}

	private static JavaAgentEventBean prepareNoSQLEvent(JavaAgentEventBean eventBean,
			NoSQLOperationalBean noSQLOperationalBean) {
		JSONArray params = new JSONArray();
		ProcessorThread.getMongoDbParameterValue(noSQLOperationalBean.getApiCallArgs(), params);
		eventBean.setEventCategory(MONGO);
		eventBean.setParameters(params);
		return eventBean;
	}

	private static JavaAgentEventBean prepareSSRFEvent(JavaAgentEventBean eventBean,
			SSRFOperationalBean ssrfOperationalBean) {
		JSONArray params = new JSONArray();
		String sourceString = eventBean.getSourceMethod();
		Object[] obj = ssrfOperationalBean.getApiCallArgs();

		if (sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2) || sourceString
				.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS) || sourceString
				.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2) || sourceString
				.equals(WEBLOGIC_OPEN_CONNECTION_METHOD)) {
			ProcessorThread.getJavaHttpRequestParameters(obj, params);
		} else if (sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD) || sourceString
				.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD)) {
			ProcessorThread.getJava9HttpClientParameters(obj, params);
		} else if (sourceString.equals(APACHE_HTTP_REQUEST_EXECUTOR_METHOD)) {
			ProcessorThread.getApacheHttpRequestParameters(obj, params);
		} else if (sourceString.equals(APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD)) {
			ProcessorThread.getApacheCommonsHttpRequestParameters(obj, params);
		} else if (sourceString.equals(OKHTTP_HTTP_ENGINE_METHOD)) {
			ProcessorThread.getOkHttpRequestParameters(obj, params);
		}

		eventBean.setParameters(params);
		return eventBean;
	}

	private boolean allowedExtensionFileIO(JSONArray params, String sourceString, String url) {
		if (JAVA_IO_FILE_INPUTSTREAM_OPEN.equals(sourceString)) {
			for (int i = 0; i < params.size(); i++) {
				String filePath = params.get(i).toString();

				if(StringUtils.containsIgnoreCase(filePath, SLASH)){
					filePath = StringUtils.substringAfterLast(filePath, SLASH);
				}

				if(StringUtils.containsIgnoreCase(url, SLASH)){
					url = StringUtils.substringAfterLast(url, SLASH);
				}

				if (StringUtils.equals(url, filePath))
					return true;
			}
		}
		return false;
	}

	private JavaAgentEventBean processStackTrace(JavaAgentEventBean eventBean,
			VulnerabilityCaseType vulnerabilityCaseType) {
		String lastNonJavaClass = StringUtils.EMPTY;
		String lastNonJavaMethod = StringUtils.EMPTY;
		int lastNonJavaLineNumber = 0;
		String klassName = null;
		boolean userclassFound = false;

		for (int i = 0; i < trace.length; i++) {
			int lineNumber = trace[i].getLineNumber();
			klassName = trace[i].getClassName();
			if (VulnerabilityCaseType.SYSTEM_COMMAND.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.SQL_DB_COMMAND.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.FILE_INTEGRITY.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.NOSQL_DB_COMMAND.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.FILE_OPERATION.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.HTTP_REQUEST.equals(vulnerabilityCaseType)) {
				rciTriggerCheck(i, eventBean, klassName);
				xxeTriggerCheck(i, eventBean, klassName);
				deserializationTriggerCheck(i, eventBean, klassName);
			}
			if (lineNumber <= 0) {
				continue;
			}
			Matcher matcher = PATTERN.matcher(klassName);
			if (!matcher.matches() && !userclassFound) {
				eventBean.setUserAPIInfo(lineNumber, klassName, trace[i].getMethodName());
				if (i > 0) {
					eventBean.setCurrentMethod(trace[i - 1].getMethodName());
				}
				userclassFound = true;
			} else if (!userclassFound && StringUtils.isNotBlank(matcher.group(5))) {
				lastNonJavaClass = trace[i].getClassName();
				lastNonJavaMethod = trace[i].getMethodName();
				lastNonJavaLineNumber = trace[i].getLineNumber();
			}
		}
		if (eventBean.getUserFileName() == null || eventBean.getUserFileName().isEmpty()) {
			eventBean.setUserAPIInfo(lastNonJavaLineNumber, lastNonJavaClass, lastNonJavaMethod);
		}
		return eventBean;
	}

	private void xxeTriggerCheck(int i, JavaAgentEventBean eventBean, String klassName) {

		if ((StringUtils.contains(klassName, XML_DOCUMENT_FRAGMENT_SCANNER_IMPL)
				&& StringUtils.equals(trace[i].getMethodName(), SCAN_DOCUMENT))
				|| (StringUtils.contains(klassName, XML_ENTITY_MANAGER)
						&& StringUtils.equals(trace[i].getMethodName(), SETUP_CURRENT_ENTITY))) {
			eventBean.getMetaData().setTriggerViaXXE(true);
			logger.log(LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_XXE_EVENT_S_S, eventBean.getId(),
					Arrays.asList(trace)), Dispatcher.class.getName());
		}
	}

	private JavaAgentEventBean getUserInfo(JavaAgentEventBean eventBean) {
		String lastNonJavaClass = StringUtils.EMPTY;
		String lastNonJavaMethod = StringUtils.EMPTY;
		int lastNonJavaLineNumber = 0;
		String klassName = null;
		boolean userclassFound = false;

		for (int i = 0; i < trace.length; i++) {
			int lineNumber = trace[i].getLineNumber();
			klassName = trace[i].getClassName();
			Matcher matcher = PATTERN.matcher(klassName);
			if (!matcher.matches() && !userclassFound) {
				eventBean.setUserAPIInfo(lineNumber, klassName, trace[i].getMethodName());
				if (i > 0) {
					eventBean.setCurrentMethod(trace[i - 1].getMethodName());
				}
				userclassFound = true;
			} else if (!userclassFound && StringUtils.isNotBlank(matcher.group(5))) {
				lastNonJavaClass = trace[i].getClassName();
				lastNonJavaMethod = trace[i].getMethodName();
				lastNonJavaLineNumber = trace[i].getLineNumber();
			}
		}
		if (eventBean.getUserFileName() == null || eventBean.getUserFileName().isEmpty()) {
			eventBean.setUserAPIInfo(lastNonJavaLineNumber, lastNonJavaClass, lastNonJavaMethod);
		}
		return eventBean;
	}

	private void deserializationTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
		if (ObjectInputStream.class.getName().equals(klassName)
				&& StringUtils.equals(trace[index].getMethodName(), READ_OBJECT)) {
			eventBean.getMetaData().setTriggerViaDeserialisation(true);
//			logger.log(LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_DESERIALISE_EVENT_S_S,
//					eventBean.getId(), Arrays.asList(trace)), Dispatcher.class.getName());

		}
	}

	private void rciTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
		if (!StringUtils.contains(trace[index].toString(), DOT_JAVA_COLON) && index > 0
				&& StringUtils.contains(trace[index - 1].toString(), DOT_JAVA_COLON)) {
			eventBean.getMetaData().setTriggerViaRCI(true);
			eventBean.getMetaData().getRciMethodsCalls().add(trace[index].toString());
			eventBean.getMetaData().getRciMethodsCalls().add(trace[index - 1].toString());
//			logger.log(LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_PROBABLE_RCI_EVENT_S_S,
//					eventBean.getId(), Arrays.asList(trace)), Dispatcher.class.getName());
		}
		if (StringUtils.contains(klassName, REFLECT_NATIVE_METHOD_ACCESSOR_IMPL)
				&& StringUtils.equals(trace[index].getMethodName(), INVOKE_0) && index > 0) {
			eventBean.getMetaData().setTriggerViaRCI(true);
			eventBean.getMetaData().getRciMethodsCalls().add(trace[index - 1].toString());
//			logger.log(LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_RCI_EVENT_S_S, eventBean.getId(),
//					Arrays.asList(trace)), Dispatcher.class.getName());
		}
	}

	private JavaAgentEventBean setGenericProperties(AbstractOperationalBean objectBean,
			JavaAgentEventBean eventBean) {
		eventBean.setApplicationUUID(K2Instrumentator.APPLICATION_UUID);
		eventBean.setPid(K2Instrumentator.VMPID);
		eventBean.setSourceMethod(objectBean.getSourceMethod());
		eventBean.setId(objectBean.getExecutionId());
		eventBean.setStartTime(objectBean.getStartTime());
		eventBean.setBlockingProcessingTime((Long) extraInfo.get(BLOCKING_END_TIME) - eventBean.getStartTime());
		return eventBean;
	}

	private JavaAgentEventBean prepareEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData,
			VulnerabilityCaseType vulnerabilityCaseType) {
		JavaAgentEventBean eventBean = new JavaAgentEventBean();
		eventBean.setHttpRequest(httpRequestBean);
		eventBean.setMetaData(metaData);
		eventBean.setCaseType(vulnerabilityCaseType.getCaseType());
		return eventBean;
	}

	public static String getDbName(String className) {
		if (StringUtils.contains(className, MSSQL_DB_IDENTIFIER))
			return MSSQL;
		else if (StringUtils.contains(className, MYSQL_DB_IDENTIFIER))
			return MYSQL;
		else if (StringUtils.contains(className, HSQL_DB_IDENTIFIER))
			return HSQL;
		else if (StringUtils.contains(className, POSTGRESQL_DB_IDENTIFIER))
			return POSTGRESQL;
		else if (StringUtils.contains(className, FIREBIRD_DB_IDENTIFIER))
			return FIREBIRD;
		else if (StringUtils.contains(className, H2_DB_IDENTIFIER))
			return H2;
		else if (StringUtils.contains(className, DERBY_DB_IDENTIFIER))
			return DERBY;
		else if (StringUtils.contains(className, IBMDB2_DB_IDENTIFIER))
			return IBMDB2;
		else if (StringUtils.contains(className, TERADATA_DB_IDENTIFIER))
			return TERADATA;
		else if (StringUtils.contains(className, ORACLE_DB_IDENTIFIER))
			return ORACLE;
		else if (StringUtils.contains(className, MARIADB_DB_IDENTIFIER))
			return MARIADB;
		else
			return UNKNOWN;

	}

	public void printDispatch() {
		try {
			logger.log(LogLevel.DEBUG,
					"==========================================================================================", Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,"Intercepted Request : " + httpRequestBean, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,"Intercepted Response : " + httpRequestBean.getHttpResponseBean(), Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,"Agent Meta : " + metaData, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,"Intercepted transaction : " + event, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,"Trace : " + Arrays.asList(trace), Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,"vulnerabilityCaseType : " + vulnerabilityCaseType, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,
					"==========================================================================================", Dispatcher.class.getName());
		} catch (Exception e) {
		}
	}

}
