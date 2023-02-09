package com.newrelic.agent.security.instrumentator.dispatcher;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.DeployedApplication;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.*;
import com.newrelic.api.agent.security.schema.operation.*;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.Nullable;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.ObjectInputStream;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.*;

/**
 * Agent utility for out of band processing and sending of events to K2 validator.
 */
public class Dispatcher implements Runnable {

    private static final String SEPARATOR_QUESTIONMARK = "?";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String ERROR = "Error : ";
    public static final String EMPTY_FILE_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String DROPPING_APPLICATION_INFO_POSTING_DUE_TO_SIZE_0 = "Dropping application info posting due to size 0 : ";
    public static final String QUESTION_CHAR = SEPARATOR_QUESTIONMARK;
    //	public static final String SLASH = "/";
    public static final String FOR_NAME = "forName";
    public static final String PUBLIC_JAVA_LANG_STRING_JAVA_IO_FILE_LIST = "public java.lang.String[] java.io.File.list()";
    public static final String DROPPING_EVENT_AS_IT_WAS_GENERATED_BY_K_2_INTERNAL_API_CALL = "Dropping event as it was generated by K2 internal API call : ";
    public static final String CURRENT_GENERIC_SERVLET_INSTANCE = "currentGenericServletInstance";
    public static final String CURRENT_GENERIC_SERVLET_METHOD_NAME = "currentGenericServletMethodName";
    public static final String UPDATED_APPLICATION_INFO_POSTED = "[STEP-9][COMPLETE][APP_INFO][DEPLOYED_APP] Updated Application info sent to Prevent-Web service : %s";
    public static final char SEPARATOR = '.';
    public static final String INSIDE_SET_REQUIRED_STACK_TRACE = "Inside setRequiredStackTrace : ";
    private static final String APPLICATION_SERVER_DETECTION_COMPLETE = "[APP_INFO][DEPLOYED_APP] Deployed application info generated : %s";
    private static final String APPLICATION_SERVER_DETECTION_STARTED = "[STEP-9][BEGIN][APP_INFO][DEPLOYED_APP] Gathering deployed application info for current process.";
    private static final String EVENT_ZERO_SENT = "[STEP-8][COMPLETE][EVENT] First event sent for validation %s";
    private static final String SENDING_EVENT_ZERO = "[EVENT] Sending first event for validation.";
    private static final String POSTING_UPDATED_APPLICATION_INFO = "[APP_INFO][DEPLOYED_APP] Sending updated application info to Prevent-Web service : %s";


    private static final Object deployedAppDetectionLock = new Object();
    public static final String S_S = "%s-%s";
    public static final String K_2_SERVICE_NAME = "K2_SERVICE_NAME";
    public static final String SEPARATOR_COLON = ":";
    public static final String SETTING_UP_USER_PROVIDED_NAME = "Setting up user provided name : ";
    public static final String NR_TRACE_ID = "trace.id";
    public static final String NR_SPAN_ID = "span.id";
    public static final String NR_IS_SAMPLED = "isSampled";
    public static final String ERROR_WHILE_SETTING_REQUIRED_STACK_TRACE_IN_EVENT = "Error while setting required stack trace in event: ";
    public static final String CREATING_NEW_DEPLOYED_APPLICATION = "Creating new deployed application";
    public static final String DEPLOYED_APP_AFTER_SET_PATH = "Deployed app after set path : ";
    public static final String DEPLOYED_APP_AFTER_PROCESSING = "Deployed app after processing : ";
    public static final String DEPLOYED_APP_AFTER_PROCESSING_1 = "Deployed app after processing 1 : ";
    public static final String ERROR_WHILE_DEPLOYED_APP_PROCESSING = "Error while deployed app processing : ";
    public static final String SERVER_NAME = "server-name";
    public static final String SEPARATOR1 = ", ";
    public static final String APP_LOCATION = "app-location";
    public static final String SKIP_COM_NEWRELIC = "com.newrelic.";
    public static final String SKIP_COM_NR = "com.nr.";
    private ExitEventBean exitEventBean;
    private AbstractOperation operation;
    private SecurityMetaData securityMetaData;
    private Map<String, Object> extraInfo = new HashMap<String, Object>();
    private boolean isNRCode = false;
    private static AtomicBoolean firstEventSent = new AtomicBoolean(false);

    public Dispatcher(AbstractOperation operation, SecurityMetaData securityMetaData) {
        this.securityMetaData = securityMetaData;
        this.operation = operation;
        extraInfo.put(BLOCKING_END_TIME, System.currentTimeMillis());
    }


    public Dispatcher(ExitEventBean exitEventBean) {
        this.exitEventBean = exitEventBean;
    }


    /**
     * Processing of hooked data on the basis of case type.
     * Followed by delegated sending of event.
     */
    @Override
    public void run() {
        try {
            if (this.exitEventBean != null) {
                EventSendPool.getInstance().sendEvent(exitEventBean);
                return;
            }
            if (!firstEventSent.get()) {
                logger.logInit(LogLevel.INFO, SENDING_EVENT_ZERO, this.getClass().getName());
            }

            if (operation == null) {
                // Invalid Event. Just drop.
                return;
            }

            JavaAgentEventBean eventBean = prepareEvent(securityMetaData.getRequest(), securityMetaData.getMetaData(),
                    operation.getCaseType(), securityMetaData.getFuzzRequestIdentifier());
            setGenericProperties(operation, eventBean);
            switch (operation.getCaseType()) {
                case REFLECTED_XSS:
                    processReflectedXSSEvent(eventBean);
                    return;
                case FILE_OPERATION:
                    FileOperation fileOperationalBean = (FileOperation) operation;
                    eventBean = processFileOperationEvent(eventBean, fileOperationalBean);
                    if (eventBean == null) {
                        return;
                    }
                    break;
                case SYSTEM_COMMAND:
                    ForkExecOperation operationalBean = (ForkExecOperation) operation;
                    eventBean = prepareSystemCommandEvent(eventBean, operationalBean);
                    break;
                case SQL_DB_COMMAND:
                    SQLOperation sqlOperation = (SQLOperation) operation;
                    eventBean = prepareSQLDbCommandEvent(Collections.singletonList(sqlOperation), eventBean);
                    break;

                case NOSQL_DB_COMMAND:
                    NoSQLOperation noSQLOperationalBean = (NoSQLOperation) operation;
                    try {
                        eventBean = prepareNoSQLEvent(eventBean, noSQLOperationalBean);
                    } catch (ParseException e) {
                        return;
                    }
                    break;

                case FILE_INTEGRITY:
                    FileIntegrityOperation fileIntegrityBean = (FileIntegrityOperation) operation;
                    eventBean = prepareFileIntegrityEvent(eventBean, fileIntegrityBean);
                    break;
                case LDAP:
                    LDAPOperation ldapOperationalBean = (LDAPOperation) operation;
                    eventBean = prepareLDAPEvent(eventBean, ldapOperationalBean);
                    break;
                case RANDOM:
                    RandomOperation randomOperationalBean = (RandomOperation) operation;
                    eventBean = prepareRandomEvent(eventBean, randomOperationalBean);
                    break;
                case HTTP_REQUEST:
                    SSRFOperation ssrfOperationalBean = (SSRFOperation) operation;
                    eventBean = prepareSSRFEvent(eventBean, ssrfOperationalBean);
                    break;
                case XPATH:
                    XPathOperation xPathOperationalBean = (XPathOperation) operation;
                    eventBean = prepareXPATHEvent(eventBean, xPathOperationalBean);
                    break;
                case SECURE_COOKIE:
                    SecureCookieOperation secureCookieOperationalBean = (SecureCookieOperation) operation;
                    eventBean = prepareSecureCookieEvent(eventBean, secureCookieOperationalBean);
                    break;
                case TRUSTBOUNDARY:
                    TrustBoundaryOperation trustBoundaryOperationalBean = (TrustBoundaryOperation) operation;
                    eventBean = prepareTrustBoundaryEvent(eventBean, trustBoundaryOperationalBean);
                    break;
                case CRYPTO:
                    HashCryptoOperation hashCryptoOperationalBean = (HashCryptoOperation) operation;
                    eventBean = prepareCryptoEvent(eventBean, hashCryptoOperationalBean);
                    break;
                case HASH:
                    HashCryptoOperation hashOperationalBean = (HashCryptoOperation) operation;
                    eventBean = prepareHashEvent(eventBean, hashOperationalBean);
                    break;
                case JAVASCRIPT_INJECTION:
                    JSInjectionOperation jsInjectionOperationalBean = (JSInjectionOperation) operation;
                    eventBean = prepareJSInjectionEvent(eventBean, jsInjectionOperationalBean);
                    break;
                case XQUERY_INJECTION:
                    XQueryOperation xQueryOperationalBean = (XQueryOperation) operation;
                    eventBean = prepareXQueryInjectionEvent(eventBean, xQueryOperationalBean);
                    break;
                default:

            }

            if (!VulnerabilityCaseType.FILE_INTEGRITY.equals(operation.getCaseType())) {
                if (VulnerabilityCaseType.FILE_OPERATION.equals(operation.getCaseType())
                        && ((FileOperation) operation).isGetBooleanAttributesCall()) {
                    eventBean = processStackTrace(eventBean, operation.getCaseType(), false);
                } else {
                    eventBean = processStackTrace(eventBean, operation.getCaseType(), true);
                }
                if (eventBean == null) {
                    return;
                }
            }

            EventSendPool.getInstance().sendEvent(eventBean);
            if (!firstEventSent.get()) {
                logger.logInit(LogLevel.INFO, String.format(EVENT_ZERO_SENT, eventBean), this.getClass().getName());
                firstEventSent.set(true);
            }
//        detectDeployedApplication();
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @Nullable
    private JavaAgentEventBean processFileOperationEvent(JavaAgentEventBean eventBean, FileOperation fileOperationalBean) {
        prepareFileEvent(eventBean, fileOperationalBean);
        String URL = StringUtils.substringBefore(securityMetaData.getRequest().getUrl(), QUESTION_CHAR);
        if (!(AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) && allowedExtensionFileIO(eventBean.getParameters(), eventBean.getSourceMethod(), URL)) {
            // Event is bypassed. Drop it.
            return null;
        }
        return eventBean;
    }


    /**
     * Validate and send if required event for REFLECTED XSS
     */
    private void processReflectedXSSEvent(JavaAgentEventBean eventBean) {
        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_DETECTION_DISABLE_RXSS, false)) {
            return;
        }
        Set<String> xssConstructs = CallbackUtils.checkForReflectedXSS(securityMetaData.getRequest(), securityMetaData.getResponse());
        if ((!xssConstructs.isEmpty() && !actuallyEmpty(xssConstructs) && StringUtils.isNotBlank(securityMetaData.getResponse().getResponseBody())) ||
                (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
            JSONArray params = new JSONArray();
            params.addAll(xssConstructs);
            params.add(securityMetaData.getResponse().getResponseBody());
            eventBean.setParameters(params);
            eventBean.setApplicationUUID(AgentInfo.getInstance().getApplicationUUID());
            eventBean.setPid(AgentInfo.getInstance().getVMPID());
            eventBean.setId(operation.getExecutionId());
            eventBean.setStartTime(operation.getStartTime());
            eventBean.setBlockingProcessingTime(
                    (Long) extraInfo.get(BLOCKING_END_TIME) - eventBean.getStartTime());

            eventBean.setApiId(operation.getApiID());
            EventSendPool.getInstance().sendEvent(eventBean);
            if (!firstEventSent.get()) {
                logger.logInit(LogLevel.INFO, String.format(EVENT_ZERO_SENT, eventBean), this.getClass().getName());
                firstEventSent.set(true);
            }
//            detectDeployedApplication();
        }
    }

    private boolean actuallyEmpty(Set<String> xssConstructs) {
        for (String xssConstruct : xssConstructs) {
            if (StringUtils.isNotBlank(xssConstruct)) {
                return false;
            }
        }
        return true;
    }


    private String getMatchPackagePrefix(String className) {
        String[] parts = StringUtils.split(className, SEPARATOR);
        if (parts.length == 1) {
            return StringUtils.EMPTY;
        }
        if (parts.length > 2) {
            return StringUtils.join(parts, SEPARATOR, 0, 2);
        } else {
            return StringUtils.join(parts, SEPARATOR, 0, parts.length - 1);
        }

    }

    private void setAppLocationStatusFile(Set<DeployedApplication> deployedApplications) {
        String appLocations = StringUtils.EMPTY;

        for (DeployedApplication deployedApplication : deployedApplications) {
            if (StringUtils.isNotBlank(deployedApplication.getDeployedPath())) {
                StringUtils.joinWith(SEPARATOR1, appLocations, deployedApplication.getDeployedPath());
            }
        }
        AgentUtils.getInstance().getStatusLogValues().put(APP_LOCATION, appLocations);
    }


    private JavaAgentEventBean prepareJSInjectionEvent(JavaAgentEventBean eventBean,
                                                       JSInjectionOperation jsInjectionOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(jsInjectionOperationalBean.getJavaScriptCode());
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareXQueryInjectionEvent(JavaAgentEventBean eventBean,
                                                           XQueryOperation xQueryOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(xQueryOperationalBean.getExpression());
        eventBean.setParameters(params);
        return eventBean;
    }


    private JavaAgentEventBean prepareXPATHEvent(JavaAgentEventBean eventBean,
                                                 XPathOperation xPathOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(xPathOperationalBean.getExpression());
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareHashEvent(JavaAgentEventBean eventBean,
                                                HashCryptoOperation hashOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(hashOperationalBean.getName());
        if (StringUtils.isNotBlank(hashOperationalBean.getProvider())) {
            params.add(hashOperationalBean.getProvider());
        }
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareCryptoEvent(JavaAgentEventBean eventBean,
                                                  HashCryptoOperation hashCryptoOperationalBean) {
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
                                                         TrustBoundaryOperation trustBoundaryOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(trustBoundaryOperationalBean.getKey());
        params.add(trustBoundaryOperationalBean.getValue());
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareRandomEvent(JavaAgentEventBean eventBean,
                                                  RandomOperation randomOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(randomOperationalBean.getClassName());
        eventBean.setEventCategory(randomOperationalBean.getEventCatgory());
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareSecureCookieEvent(JavaAgentEventBean eventBean,
                                                        SecureCookieOperation secureCookieOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(secureCookieOperationalBean.getValue());
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareLDAPEvent(JavaAgentEventBean eventBean, LDAPOperation ldapOperationalBean) {
        JSONArray params = new JSONArray();
        JSONObject object = new JSONObject();
        object.put(NAME, ldapOperationalBean.getName());
        object.put(FILTER, ldapOperationalBean.getFilter());
        params.add(object);
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareFileIntegrityEvent(JavaAgentEventBean eventBean,
                                                         FileIntegrityOperation fileIntegrityBean) {
        JSONArray params = new JSONArray();
        params.add(fileIntegrityBean.getFileName());
        eventBean.setParameters(params);
//		eventBean.setUserAPIInfo(fileIntegrityBean.getLineNumber(), fileIntegrityBean.getClassName(),
//				fileIntegrityBean.getUserMethodName());
        return eventBean;
    }

    private JavaAgentEventBean prepareSQLDbCommandEvent(List<SQLOperation> operationalList,
                                                        JavaAgentEventBean eventBean) {
        JSONArray params = new JSONArray();
        for (SQLOperation operationalBean : operationalList) {
            JSONObject query = new JSONObject();
            query.put(QUERY, operationalBean.getQuery());
            if(operationalBean.getParams() != null) {
                query.put(PARAMETERS, new JSONObject(operationalBean.getParams()));
            }
            params.add(query);
        }
        eventBean.setParameters(params);
        eventBean.setEventCategory(operationalList.get(0).getDbName());
        return eventBean;
    }

    private JavaAgentEventBean prepareSystemCommandEvent(JavaAgentEventBean eventBean,
                                                         ForkExecOperation operationalBean) {
        JSONArray params = new JSONArray();
        params.add(operationalBean.getCommand());
        if (operationalBean.getEnvironment() != null) {
            params.add(new JSONObject(operationalBean.getEnvironment()));
        }
        eventBean.setParameters(params);
        return eventBean;
    }

    private static JavaAgentEventBean prepareFileEvent(JavaAgentEventBean eventBean,
                                                       FileOperation fileOperationalBean) {
        JSONArray params = new JSONArray();
        params.addAll(fileOperationalBean.getFileName());
        eventBean.setParameters(params);
        return eventBean;
    }

    private static JavaAgentEventBean prepareNoSQLEvent(JavaAgentEventBean eventBean,
                                                        NoSQLOperation noSQLOperationalBean) throws ParseException {
        JSONArray params = new JSONArray();
        eventBean.setEventCategory(MONGO);
        JSONParser jsonParser = new JSONParser();
        params.addAll((JSONArray) jsonParser.parse(noSQLOperationalBean.getData().toString()));
        eventBean.setParameters(params);
        return eventBean;
    }

    private static JavaAgentEventBean prepareSSRFEvent(JavaAgentEventBean eventBean,
                                                       SSRFOperation ssrfOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(ssrfOperationalBean.getArg());
        eventBean.setParameters(params);
        if (ssrfOperationalBean.isJNDILookup()) {
            eventBean.setEventCategory("JNDILookup");
        }
        return eventBean;
    }

    private boolean allowedExtensionFileIO(JSONArray params, String sourceString, String url) {
        if (JAVA_IO_FILE_INPUTSTREAM_OPEN.equals(sourceString)) {
            for (int i = 0; i < params.size(); i++) {
                String filePath = params.get(i).toString();

                if (StringUtils.containsIgnoreCase(filePath, File.separator)) {
                    filePath = StringUtils.substringAfterLast(filePath, File.separator);
                }

                if (StringUtils.containsIgnoreCase(url, File.separator)) {
                    url = StringUtils.substringAfterLast(url, File.separator);
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
        for (int i = 0; i < operation.getStackTrace().length; i++) {
            // TODO : check this sequence. Why this is being set from inside Deserialisation check.
            if (isNRCode) {
                logger.log(LogLevel.DEBUG, DROPPING_EVENT_AS_IT_WAS_GENERATED_BY_K_2_INTERNAL_API_CALL + eventBean,
                        Dispatcher.class.getName());
                return null;
            }
            klassName = operation.getStackTrace()[i].getClassName();
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
        return eventBean;
    }

    private void xxeTriggerCheck(int i, JavaAgentEventBean eventBean, String klassName) {

        if ((StringUtils.contains(klassName, XML_DOCUMENT_FRAGMENT_SCANNER_IMPL)
                && StringUtils.equals(operation.getStackTrace()[i].getMethodName(), SCAN_DOCUMENT))
                || (StringUtils.contains(klassName, XML_ENTITY_MANAGER)
                && StringUtils.equals(operation.getStackTrace()[i].getMethodName(), SETUP_CURRENT_ENTITY))) {
            eventBean.getMetaData().setTriggerViaXXE(true);
        }
    }

    private void deserializationTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_DETECTION_DISABLE_DESERIALIZATION, false)) {
            return;
        }
        if (ObjectInputStream.class.getName().equals(klassName)
                && StringUtils.equals(operation.getStackTrace()[index].getMethodName(), READ_OBJECT)) {
            eventBean.getMetaData().setTriggerViaDeserialisation(true);
        }

        if (StringUtils.startsWithAny(klassName, SKIP_COM_NEWRELIC, SKIP_COM_NR)) {
            isNRCode = true;
        }
    }

    private void rciTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
        if (NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_DETECTION_DISABLE_RCI, false)) {
            return;
        }

        if (operation.getStackTrace()[index].getLineNumber() <= 0 && index > 0
                && operation.getStackTrace()[index - 1].getLineNumber() > 0 && StringUtils.isNotBlank(operation.getStackTrace()[index - 1].getFileName())) {
            eventBean.getMetaData().setTriggerViaRCI(true);
            eventBean.getMetaData().getRciMethodsCalls().add(AgentUtils.stackTraceElementToString(operation.getStackTrace()[index]));
            eventBean.getMetaData().getRciMethodsCalls().add(AgentUtils.stackTraceElementToString(operation.getStackTrace()[index - 1]));
        }
        if (StringUtils.contains(klassName, REFLECT_NATIVE_METHOD_ACCESSOR_IMPL)
                && StringUtils.equals(operation.getStackTrace()[index].getMethodName(), INVOKE_0) && index > 0) {
            eventBean.getMetaData().setTriggerViaRCI(true);
            eventBean.getMetaData().getRciMethodsCalls().add(AgentUtils.stackTraceElementToString(operation.getStackTrace()[index - 1]));
        }
    }

    private JavaAgentEventBean setGenericProperties(AbstractOperation objectBean, JavaAgentEventBean eventBean) {
        eventBean.setApplicationUUID(AgentInfo.getInstance().getApplicationUUID());
        eventBean.setPid(AgentInfo.getInstance().getVMPID());
        eventBean.setSourceMethod(objectBean.getSourceMethod());
        eventBean.setId(objectBean.getExecutionId());
        eventBean.setStartTime(objectBean.getStartTime());
        eventBean.setBlockingProcessingTime((Long) extraInfo.get(BLOCKING_END_TIME) - eventBean.getStartTime());
        eventBean.setApiId(objectBean.getApiID());
        eventBean.setUserAPIInfo(operation.getUserClassEntity().getUserClassElement().getLineNumber(),
                operation.getUserClassEntity().getUserClassElement().getClassName(),
                operation.getUserClassEntity().getUserClassElement().getMethodName());
        return eventBean;
    }

    private JavaAgentEventBean prepareEvent(HttpRequest httpRequestBean, AgentMetaData metaData,
                                            VulnerabilityCaseType vulnerabilityCaseType, K2RequestIdentifier k2RequestIdentifier) {
        JavaAgentEventBean eventBean = new JavaAgentEventBean();
        eventBean.setHttpRequest(httpRequestBean);
        eventBean.setMetaData(metaData);
        eventBean.setCaseType(vulnerabilityCaseType.getCaseType());
        eventBean.setIsAPIBlocked(metaData.isApiBlocked());
        eventBean.setStacktrace(operation.getStackTrace());
        eventBean.setIASTRequest(k2RequestIdentifier.getK2Request());
        if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled() && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
            eventBean.setIsIASTEnable(true);
        }
        return eventBean;
    }

}