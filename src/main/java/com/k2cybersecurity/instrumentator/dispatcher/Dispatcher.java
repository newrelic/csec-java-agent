package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.custom.ClassloaderAdjustments;
import com.k2cybersecurity.instrumentator.custom.ServletContextInfo;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEComponentsService;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
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
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.ObjectInputStream;
import java.util.*;
import java.util.regex.Pattern;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class Dispatcher implements Runnable {

	private static final Pattern PATTERN;
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String ERROR = "Error : ";
	public static final String EMPTY_FILE_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	public static final String DROPPING_APPLICATION_INFO_POSTING_DUE_TO_SIZE_0 = "Dropping application info posting due to size 0 : ";
	public static final String QUESTION_CHAR = "?";
	public static final String SLASH = "/";
	public static final String FOR_NAME = "forName";
	public static final String SUN_REFLECT_COM_K_2_CYBERSECURITY_NET_BYTEBUDDY = "sun.reflect.com.k2cybersecurity.net.bytebuddy";
	public static final String PUBLIC_JAVA_LANG_STRING_JAVA_IO_FILE_LIST = "public java.lang.String[] java.io.File.list()";
	public static final String DROPPING_EVENT_AS_IT_WAS_GENERATED_BY_K_2_INTERNAL_API_CALL = "Dropping event as it was generated by K2 internal API call : ";
	public static final String CURRENT_GENERIC_SERVLET_INSTANCE = "currentGenericServletInstance";
	public static final String CURRENT_GENERIC_SERVLET_METHOD_NAME = "currentGenericServletMethodName";
	public static final String UPDATED_APPLICATION_INFO_POSTED = "Updated application info posted : ";
	public static final char SEPARATOR = '.';
	public static final String INSIDE_SET_REQUIRED_STACK_TRACE = "Inside setRequiredStackTrace : ";
	public static final String STRING_COLON = " : ";
	private HttpRequestBean httpRequestBean;
	private AgentMetaData metaData;
	private Object event;
	private StackTraceElement[] trace;
	private VulnerabilityCaseType vulnerabilityCaseType;
	private Map<String, Object> extraInfo = new HashMap<String, Object>();
	private boolean isGeneratedByBuddy = false;
	private Object currentGenericServletInstance;
	private String currentGenericServletMethodName = StringUtils.EMPTY;
	private UserClassEntity userClassEntity;

	static {
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
	}

	public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, Object event,
			VulnerabilityCaseType vulnerabilityCaseType) {
		this.httpRequestBean = httpRequestBean;
		this.metaData = metaData;
		this.event = event;
		this.vulnerabilityCaseType = vulnerabilityCaseType;
		extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());
		currentGenericServletInstance = ((AbstractOperationalBean)event).getCurrentGenericServletInstance();
		currentGenericServletMethodName = ((AbstractOperationalBean)event).getCurrentGenericServletMethodName();
		trace = ((AbstractOperationalBean)event).getStackTrace();
		this.userClassEntity = ((AbstractOperationalBean)event).getUserClassEntity();
	}

	public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, Object event,
					  VulnerabilityCaseType vulnerabilityCaseType, String currentGenericServletMethodName,
					  Object currentGenericServletInstance,
					  StackTraceElement[] stackTrace, UserClassEntity userClassEntity) {
		this.httpRequestBean = httpRequestBean;
		this.metaData = metaData;
		this.event = event;
		this.vulnerabilityCaseType = vulnerabilityCaseType;
		extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());
		this.currentGenericServletInstance = currentGenericServletInstance;
		this.currentGenericServletMethodName = currentGenericServletMethodName;
		this.trace = stackTrace;
		this.userClassEntity = userClassEntity;
	}

	public Dispatcher(HttpRequestBean httpRequestBean, VulnerabilityCaseType reflectedXss,
			String sourceString, String exectionId, long startTime, String currentGenericServletMethodName,
					  Object currentGenericServletInstance,
					  StackTraceElement[] stackTrace, UserClassEntity userClassEntity) {
		this.httpRequestBean = httpRequestBean;
		this.vulnerabilityCaseType = reflectedXss;
		extraInfo.put(SOURCESTRING, sourceString);
		extraInfo.put(EXECUTIONID, exectionId);
		extraInfo.put(STARTTIME, startTime);
		extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());

		this.currentGenericServletInstance = currentGenericServletInstance;
		this.currentGenericServletMethodName = currentGenericServletMethodName;
		this.trace = stackTrace;
		this.userClassEntity = userClassEntity;
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
					eventBean.setBlockingProcessingTime(
							(Long) extraInfo.get(BLOCKING_END_TIME) - eventBean.getStartTime());

					eventBean.setUserAPIInfo(userClassEntity.getUserClassElement().getLineNumber(),
							userClassEntity.getUserClassElement().getClassName(),
							userClassEntity.getUserClassElement().getMethodName());

					setRequiredStackTracePartToEvent(eventBean);
					EventSendPool.getInstance().sendEvent(eventBean);
//					System.out.println("============= Event Start ============");
//					System.out.println(eventBean);
//					System.out.println("============= Event End ============");
				}
				return;
			}
		} catch (Throwable e) {
			logger.log(LogLevel.ERROR, ERROR, e, Dispatcher.class.getName());
		}

		if (event == null) {
//			System.out.println("------- Invalid event -----------");
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
		case SYSTEM_EXIT:
			SystemExitOperationalBean systemExitOperationalBean = (SystemExitOperationalBean) event;
			eventBean = setGenericProperties(systemExitOperationalBean, eventBean);
			eventBean = prepareSystemExitEvent(eventBean, systemExitOperationalBean);

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
		case JAVASCRIPT_INJECTION:
			JSInjectionOperationalBean jsInjectionOperationalBean = (JSInjectionOperationalBean) event;
			eventBean = setGenericProperties(jsInjectionOperationalBean, eventBean);
			eventBean = prepareJSInjectionEvent(eventBean, jsInjectionOperationalBean);
			break;
		case XQUERY_INJECTION:
			XQueryOperationalBean xQueryOperationalBean = (XQueryOperationalBean) event;
			eventBean = setGenericProperties(xQueryOperationalBean, eventBean);
			eventBean = prepareXQueryInjectionEvent(eventBean, xQueryOperationalBean);
			break;
		default:

		}

		if (!VulnerabilityCaseType.FILE_INTEGRITY.equals(vulnerabilityCaseType)) {
			if (VulnerabilityCaseType.FILE_OPERATION.equals(vulnerabilityCaseType)
					&& ((FileOperationalBean) event).isGetBooleanAttributesCall()) {
				eventBean = processStackTrace(eventBean, vulnerabilityCaseType, false);
			} else {
				eventBean = processStackTrace(eventBean, vulnerabilityCaseType, true);
			}
			if (eventBean == null) {
				return;
			}
		}

		setRequiredStackTracePartToEvent(eventBean);
		EventSendPool.getInstance().sendEvent(eventBean);

		if(userClassEntity.isCalledByUserCode()) {
			detectAndSendDeployedAppInfo();
		}
//		System.out.println("============= Event Start ============");
//		System.out.println(eventBean);
//		System.out.println("============= Event End ============");
	}

	private void setRequiredStackTracePartToEvent(JavaAgentEventBean eventBean) {
		try {
			stackPreProcess();
			int fromLoc = 0;
			int toLoc = this.trace.length;
//		logger.log(LogLevel.DEBUG, INSIDE_SET_REQUIRED_STACK_TRACE + eventBean.getId() + STRING_COLON + JsonConverter.toJSON(userClassEntity) + STRING_COLON + JsonConverter.toJSON(Arrays.asList(trace)), Dispatcher.class.getName());
			if(metaData.isK2FuzzRequest()){
				eventBean.setCompleteStacktrace(Arrays.asList(trace));
			}

			if (userClassEntity.isCalledByUserCode()) {
				toLoc = userClassEntity.getTraceLocationEnd();
				String packageName = getMatchPackagePrefix(userClassEntity.getUserClassElement().getClassName());
				if (StringUtils.isBlank(packageName)) {
					setFiniteSizeStackTrace(eventBean);
				} else {
					int i = toLoc;
					for (i = toLoc; i >= 0; i--) {
						if (!StringUtils.startsWith(trace[i].getClassName(), packageName)) {
							break;
						}
					}
					fromLoc = i;
//				logger.log(LogLevel.DEBUG, "Setting setRequiredStackTracePart by auto detect : " + eventBean.getId(), Dispatcher.class.getName());
					eventBean.setStacktrace(Arrays.asList(Arrays.copyOfRange(this.trace, Math.max(fromLoc, 0),
							Math.min(toLoc + 1, trace.length - 1) + 1)));
				}
			} else {
				setFiniteSizeStackTrace(eventBean);
			}
		}catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR, e, Dispatcher.class.getName());
		}
	}

	private void stackPreProcess() {
		int i = 1;
		for(i = 1; i<trace.length; i++){
			if(!StringUtils.startsWith(trace[i].getClassName(), ClassloaderAdjustments.K2_BOOTSTAP_LOADED_PACKAGE_NAME)){
				break;
			}
		}
		trace = Arrays.copyOfRange(trace, i, trace.length);
		userClassEntity.setTraceLocationEnd(userClassEntity.getTraceLocationEnd() - i);
	}

	private void setFiniteSizeStackTrace(JavaAgentEventBean eventBean) {
//		logger.log(LogLevel.DEBUG, "Setting setFiniteSizeStackTrace : " + eventBean.getId(), Dispatcher.class.getName());
		int fromLoc = 0;
		int toLoc = this.trace.length;
		fromLoc = Math.max(userClassEntity.getTraceLocationEnd() - 4, 0);
		toLoc = Math.min(userClassEntity.getTraceLocationEnd() + 1, trace.length - 1);
		eventBean.setStacktrace(Arrays.asList(Arrays.copyOfRange(this.trace, fromLoc, toLoc + 1)));
	}

	private String getMatchPackagePrefix(String className){
		String[] parts = StringUtils.split(className, SEPARATOR);
		if(parts.length == 1){
			return StringUtils.EMPTY;
		}
		if (parts.length > 2) {
			return StringUtils.join(parts, SEPARATOR, 0, 2);
		} else {
			return StringUtils.join(parts, SEPARATOR, 0, parts.length - 1);
		}

	}

	private boolean detectAndSendDeployedAppInfo() {
		if (!ServletContextInfo.getInstance().getContextMap().containsKey(httpRequestBean.getContextPath())) {
			DeployedApplication deployedApplication = new DeployedApplication();
			ServletContextInfo.getInstance().getContextMap().put(httpRequestBean.getContextPath(), deployedApplication);
			logger.log(LogLevel.INFO, "Creating new deployed application", Dispatcher.class.getName());
			deployedApplication.setDeployedPath(AgentUtils.getInstance().detectDeployedApplicationPath(
					userClassEntity.getUserClassElement().getClassName(), currentGenericServletInstance,
					userClassEntity.getUserClassElement().getMethodName()));
			logger.log(LogLevel.INFO, "Deployed app after set path : " + deployedApplication, Dispatcher.class.getName());
			boolean ret = false;
			try {
				ret = ServletContextInfo.getInstance().processServletContext(httpRequestBean, deployedApplication);
				logger.log(LogLevel.INFO, "Deployed app after processing : " + deployedApplication + " :: " + ret, Dispatcher.class.getName());
				HashGenerator.updateShaAndSize(deployedApplication);
				logger.log(LogLevel.INFO, "Deployed app after processing 1 : " + deployedApplication + " :: " + ret, Dispatcher.class.getName());
			} catch (Throwable e){
				logger.log(LogLevel.ERROR, "Error while deployed app processing : " + deployedApplication, e, Dispatcher.class.getName());
				ret = false;
			}
			if (deployedApplication.isEmpty() || StringUtils.isBlank(deployedApplication.getSha256()) || StringUtils.equals(deployedApplication.getSha256(), EMPTY_FILE_SHA)) {
				logger.log(LogLevel.ERROR, DROPPING_APPLICATION_INFO_POSTING_DUE_TO_SIZE_0 + deployedApplication,
						Dispatcher.class.getName());
				ServletContextInfo.getInstance().getContextMap().remove(httpRequestBean.getContextPath());
				return false;
			}


//			System.out.println("Processed App Info : " + deployedApplication);
			ApplicationInfoBean applicationInfoBean = K2Instrumentator.APPLICATION_INFO_BEAN;

			applicationInfoBean.getServerInfo().setName(ServletContextInfo.getInstance().getServerInfo());

			K2Instrumentator.JA_HEALTH_CHECK.setProtectedServer(ServletContextInfo.getInstance().getServerInfo());

			if (!applicationInfoBean.getServerInfo().getDeployedApplications().contains(deployedApplication)) {
				applicationInfoBean.getServerInfo().getDeployedApplications().add(deployedApplication);
				EventSendPool.getInstance().sendEvent(applicationInfoBean.toString());
				logger.log(LogLevel.INFO, UPDATED_APPLICATION_INFO_POSTED + applicationInfoBean,
						Dispatcher.class.getName());
				ScanComponentData scanComponentData = CVEComponentsService.getAllComponents(deployedApplication);
				EventSendPool.getInstance().sendEvent(scanComponentData.toString());
//				System.out.println("============= AppInfo Start ============");
//				System.out.println(applicationInfoBean);
//				System.out.println("============= AppInfo End ============");
			} else {
                //TODO: Handle cases where the port list of a deployed application is lost as the deployed application is already existing.
			}
			return true;
		} else {
			if(!ServletContextInfo.getInstance().getContextMap().get(httpRequestBean.getContextPath()).getPorts().contains(httpRequestBean.getServerPort())){
				DeployedApplication deployedApplication = ServletContextInfo.getInstance().getContextMap().get(httpRequestBean.getContextPath());
				deployedApplication.getPorts().add(httpRequestBean.getServerPort());
				EventSendPool.getInstance().sendEvent(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
			}
			return true;
		}
	}



	private JavaAgentEventBean prepareJSInjectionEvent(JavaAgentEventBean eventBean,
			JSInjectionOperationalBean jsInjectionOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(jsInjectionOperationalBean.getJavaScriptCode());
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareXQueryInjectionEvent(JavaAgentEventBean eventBean,
			XQueryOperationalBean xQueryOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(xQueryOperationalBean.getExpression());
		eventBean.setParameters(params);
		return eventBean;
	}

	private JavaAgentEventBean prepareSystemExitEvent(JavaAgentEventBean eventBean,
			SystemExitOperationalBean systemExitOperationalBean) {
		JSONArray params = new JSONArray();
		params.add(systemExitOperationalBean.getExitCode());
		eventBean.setParameters(params);
		return eventBean;
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
//		eventBean.setUserAPIInfo(fileIntegrityBean.getLineNumber(), fileIntegrityBean.getClassName(),
//				fileIntegrityBean.getUserMethodName());
		eventBean.setUserAPIInfo(userClassEntity.getUserClassElement().getLineNumber(),
				userClassEntity.getUserClassElement().getClassName(),
				userClassEntity.getUserClassElement().getMethodName());
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
		K2Instrumentator.JA_HEALTH_CHECK.getProtectedDB().add(MONGO);
		return eventBean;
	}

	private static JavaAgentEventBean prepareSSRFEvent(JavaAgentEventBean eventBean,
			SSRFOperationalBean ssrfOperationalBean) {
		JSONArray params = new JSONArray();
		String sourceString = eventBean.getSourceMethod();
		Object[] obj = ssrfOperationalBean.getApiCallArgs();

		if (sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2) || sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS)
				|| sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2)
				|| sourceString.equals(WEBLOGIC_OPEN_CONNECTION_METHOD)) {
			ProcessorThread.getJavaHttpRequestParameters(obj, params);
		} else if (sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD)
				|| sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD)) {
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

				if (StringUtils.containsIgnoreCase(filePath, SLASH)) {
					filePath = StringUtils.substringAfterLast(filePath, SLASH);
				}

				if (StringUtils.containsIgnoreCase(url, SLASH)) {
					url = StringUtils.substringAfterLast(url, SLASH);
				}

				if (StringUtils.equals(url, filePath))
					return true;
			}
		}
		return false;
	}

	private JavaAgentEventBean processStackTrace(JavaAgentEventBean eventBean,
			VulnerabilityCaseType vulnerabilityCaseType, boolean deserialisationCheck) {

		String klassName = null;

		for (int i = 0; i < trace.length; i++) {
			if (isGeneratedByBuddy) {
				logger.log(LogLevel.DEBUG, DROPPING_EVENT_AS_IT_WAS_GENERATED_BY_K_2_INTERNAL_API_CALL + eventBean,
						Dispatcher.class.getName());
				return null;
			}
			klassName = trace[i].getClassName();
			if (VulnerabilityCaseType.SYSTEM_COMMAND.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.SQL_DB_COMMAND.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.FILE_INTEGRITY.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.NOSQL_DB_COMMAND.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.FILE_OPERATION.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.HTTP_REQUEST.equals(vulnerabilityCaseType)
					|| VulnerabilityCaseType.SYSTEM_EXIT.equals(vulnerabilityCaseType)) {
				rciTriggerCheck(i, eventBean, klassName);
				xxeTriggerCheck(i, eventBean, klassName);
				if (deserialisationCheck) {
					deserializationTriggerCheck(i, eventBean, klassName);
				}
			}
		}
		eventBean.setUserAPIInfo(userClassEntity.getUserClassElement().getLineNumber(),
				userClassEntity.getUserClassElement().getClassName(),
				userClassEntity.getUserClassElement().getMethodName());
		return eventBean;
	}

	private void xxeTriggerCheck(int i, JavaAgentEventBean eventBean, String klassName) {

		if ((StringUtils.contains(klassName, XML_DOCUMENT_FRAGMENT_SCANNER_IMPL)
				&& StringUtils.equals(trace[i].getMethodName(), SCAN_DOCUMENT))
				|| (StringUtils.contains(klassName, XML_ENTITY_MANAGER)
						&& StringUtils.equals(trace[i].getMethodName(), SETUP_CURRENT_ENTITY))) {
			eventBean.getMetaData().setTriggerViaXXE(true);
			logger.log(LogLevel.DEBUG,
					String.format(PRINTING_STACK_TRACE_FOR_XXE_EVENT_S_S, eventBean.getId(), Arrays.asList(trace)),
					Dispatcher.class.getName());
		}
	}

	private void deserializationTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
		if (ObjectInputStream.class.getName().equals(klassName)
				&& StringUtils.equals(trace[index].getMethodName(), READ_OBJECT)) {
			eventBean.getMetaData().setTriggerViaDeserialisation(true);
//				JSONArray jsonArray = new JSONArray();
//				jsonArray.addAll(Arrays.asList(trace));
//				eventBean.setStacktrace(jsonArray);
//				logger.log(LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_DESERIALISE_EVENT_S_S,
//						eventBean.getId(), Arrays.asList(trace)), Dispatcher.class.getName());
		}

		if (StringUtils.startsWith(klassName, SUN_REFLECT_COM_K_2_CYBERSECURITY_NET_BYTEBUDDY)) {
			isGeneratedByBuddy = true;
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

	private JavaAgentEventBean setGenericProperties(AbstractOperationalBean objectBean, JavaAgentEventBean eventBean) {
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
		eventBean.setValidationResponseRequired(ProtectionConfig.getInstance().getGenerateEventResponse());
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
					"==========================================================================================",
					Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG, "Intercepted Request : " + httpRequestBean, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG, "Intercepted Response : " + httpRequestBean.getHttpResponseBean(),
					Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG, "Agent Meta : " + metaData, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG, "Intercepted transaction : " + event, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG, "Trace : " + Arrays.asList(trace), Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG, "vulnerabilityCaseType : " + vulnerabilityCaseType, Dispatcher.class.getName());

			logger.log(LogLevel.DEBUG,
					"==========================================================================================",
					Dispatcher.class.getName());
		} catch (Throwable e) {
		}
	}

}