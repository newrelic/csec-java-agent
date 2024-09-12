package com.newrelic.agent.security.instrumentator.dispatcher;

import com.google.gson.Gson;
import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.helper.DynamoDBRequestConverter;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.DeployedApplication;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.instrumentation.helpers.AppServerInfoHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.SystemCommandUtils;
import com.newrelic.api.agent.security.schema.*;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
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
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.*;

/**
 * Agent utility for out of band processing and sending of events to K2 validator.
 */
public class Dispatcher implements Callable {

    private static final String SEPARATOR_QUESTIONMARK = "?";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String ERROR = "Error : ";
    public static final String EMPTY_FILE_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String DROPPING_APPLICATION_INFO_POSTING_DUE_TO_SIZE_0 = "Dropping application info posting due to size 0 : ";
    public static final String QUESTION_CHAR = SEPARATOR_QUESTIONMARK;
    public static final char SEPARATOR = '.';
    private static final String EVENT_ZERO_SENT = "[STEP-8] => First event sent for validation. Security agent started successfully. %s";
    private static final String SENDING_EVENT_ZERO = "[EVENT] Sending first event for validation. Security agent started successfully ";
    private static final String POSTING_UPDATED_APPLICATION_INFO = "[APP_INFO][DEPLOYED_APP] Sending updated application info to Security Engine : %s";

    public static final String SEPARATOR1 = ", ";
    public static final String APP_LOCATION = "app-location";
    public static final String REDIS_MODE = "mode";
    public static final String REDIS_ARGUMENTS = "arguments";
    public static final String REDIS_TYPE = "type";
    public static final String SYSCOMMAND_ENVIRONMENT = "environment";
    public static final String SYSCOMMAND_SCRIPT_CONTENT = "script-content";
    public static final String UNABLE_TO_CONVERT_OPERATION_TO_EVENT = "Unable to convert operation to event: %s, %s, %s";
    public static final String COOKIE_NAME = "name";
    public static final String COOKIE_VALUE = "value";
    public static final String COOKIE_IS_SECURE = "isSecure";
    public static final String COOKIE_IS_HTTP_ONLY = "isHttpOnly";
    public static final String COOKIE_IS_SAME_SITE_STRICT = "isSameSiteStrict";
    private ExitEventBean exitEventBean;
    private AbstractOperation operation;
    private SecurityMetaData securityMetaData;
    private Map<String, Object> extraInfo = new HashMap<String, Object>();
    private boolean isNRCode = false;
    private static AtomicBoolean firstEventSent = new AtomicBoolean(false);
    private final String SQL_STORED_PROCEDURE ="SQL_STORED_PROCEDURE";

    public ExitEventBean getExitEventBean() {
        return exitEventBean;
    }

    public AbstractOperation getOperation() {
        return operation;
    }

    public SecurityMetaData getSecurityMetaData() {
        return securityMetaData;
    }

    private static Gson GsonUtil = new Gson();

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
    public Object call() throws Exception {
        try {
            if (this.exitEventBean != null) {
                EventSendPool.getInstance().sendEvent(exitEventBean);
                return null;
            }
            if (!firstEventSent.get()) {
                logger.logInit(LogLevel.INFO, SENDING_EVENT_ZERO, this.getClass().getName());
            }

            if (operation == null) {
                // Invalid Event. Just drop.
                return null;
            }

            JavaAgentEventBean eventBean = prepareEvent(securityMetaData.getRequest(), securityMetaData.getMetaData(),
                    operation.getCaseType(), securityMetaData.getFuzzRequestIdentifier());
            setGenericProperties(operation, eventBean);
            switch (operation.getCaseType()) {
                case REFLECTED_XSS:
                    processReflectedXSSEvent(eventBean);
                    return null;
                case FILE_OPERATION:
                    FileOperation fileOperationalBean = (FileOperation) operation;
                    eventBean = processFileOperationEvent(eventBean, fileOperationalBean);
                    if (eventBean == null) {
                        return null;
                    }
                    break;
                case SYSTEM_COMMAND:
                    ForkExecOperation operationalBean = (ForkExecOperation) operation;
                    eventBean = prepareSystemCommandEvent(eventBean, operationalBean);
                    break;
                case SQL_DB_COMMAND:
                    if (operation instanceof SQLOperation) {
                        eventBean = prepareSQLDbCommandEvent((SQLOperation) operation, eventBean);
                        break;
                    } else if (operation instanceof BatchSQLOperation) {
                        eventBean = prepareSQLDbCommandEvent((BatchSQLOperation) operation, eventBean);
                        break;
                    }
                case NOSQL_DB_COMMAND:
                    if(operation instanceof SQLOperation) {
                        eventBean = prepareSQLDbCommandEvent((SQLOperation) operation, eventBean);
                        break;
                    } else if (operation instanceof BatchSQLOperation) {
                        eventBean = prepareSQLDbCommandEvent((BatchSQLOperation) operation, eventBean);
                        break;
                    } else if (operation instanceof NoSQLOperation) {
                        eventBean = prepareNoSQLEvent(eventBean, (NoSQLOperation) operation);
                        break;
                    }

                case DYNAMO_DB_COMMAND:
                    DynamoDBOperation dynamoDBOperation = (DynamoDBOperation) operation;
                    eventBean = prepareDynamoDBEvent(eventBean, dynamoDBOperation);
                    if (eventBean == null) {
                        return null;
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
                    SecureCookieOperationSet secureCookieOperationalBean = (SecureCookieOperationSet) operation;
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
                case CACHING_DATA_STORE:
                    if(operation instanceof RedisOperation) {
                        RedisOperation redisOperation = (RedisOperation) operation;
                        eventBean = prepareCachingDataStoreEvent(eventBean, redisOperation);
                    } else if (operation instanceof JCacheOperation) {
                        JCacheOperation jCacheOperation = (JCacheOperation) operation;
                        eventBean = prepareJCacheCachingDataStoreEvent(eventBean, jCacheOperation);
                    } else if (operation instanceof MemcachedOperation) {
                        MemcachedOperation memcachedOperationalBean = (MemcachedOperation) operation;
                        eventBean = prepareMemcachedEvent(eventBean, memcachedOperationalBean);
                    }
                    break;
                case SOLR_DB_REQUEST:
                    SolrDbOperation solrDbOperation = (SolrDbOperation) operation;
                    eventBean = prepareSolrDbRequestEvent(eventBean, solrDbOperation);
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
                    return null;
                }
            }

            EventSendPool.getInstance().sendEvent(eventBean);
            if (!firstEventSent.get()) {
                logger.logInit(LogLevel.INFO, String.format(EVENT_ZERO_SENT, eventBean), this.getClass().getName());
                firstEventSent.set(true);
            }
//        detectDeployedApplication();
        } catch (Throwable e) {
            logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format(UNABLE_TO_CONVERT_OPERATION_TO_EVENT, operation.getApiID(), operation.getSourceMethod(), JsonConverter.getObjectMapper().writeValueAsString(operation.getUserClassEntity())), e,
                    this.getClass().getName());
            Agent.getInstance().reportIncident(LogLevel.WARNING, String.format(UNABLE_TO_CONVERT_OPERATION_TO_EVENT, operation.getApiID(), operation.getSourceMethod(), JsonConverter.getObjectMapper().writeValueAsString(operation.getUserClassEntity())), e,
                    this.getClass().getName());
        }
        return null;
    }

    private JavaAgentEventBean prepareSolrDbRequestEvent(JavaAgentEventBean eventBean, SolrDbOperation solrDbOperation) {
        JSONArray params = new JSONArray();
        JSONObject request = new JSONObject();
        request.put("collection", solrDbOperation.getCollection());
        request.put("method", solrDbOperation.getMethod());
        request.put("connectionURL", solrDbOperation.getConnectionURL());
        request.put("path", solrDbOperation.getPath());
        request.put("params", solrDbOperation.getParams());
        request.put("documents", solrDbOperation.getDocuments());
        params.add(request);
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareCachingDataStoreEvent(JavaAgentEventBean eventBean, RedisOperation redisOperation) {
        JSONArray params = new JSONArray();
        for (Object data : redisOperation.getArguments()) {
            params.add(data);
        }
        JSONObject command = new JSONObject();
        command.put(REDIS_MODE, redisOperation.getMode());
        command.put(REDIS_ARGUMENTS, params);
        command.put(REDIS_TYPE, redisOperation.getType());
        JSONArray parameter = new JSONArray();
        parameter.add(command);
        eventBean.setParameters(parameter);
        return eventBean;
    }

    private JavaAgentEventBean prepareJCacheCachingDataStoreEvent(JavaAgentEventBean eventBean, JCacheOperation jCacheOperation) {
        JSONArray params = new JSONArray();
        for (Object data : jCacheOperation.getArguments()) {
            if (isPrimitiveType(data.getClass())) {
                params.add(data);
            } else {
                params.add(GsonUtil.toJson(data));
            }
        }

        JSONObject command = new JSONObject();
        command.put(REDIS_ARGUMENTS, params);
        command.put(REDIS_TYPE, jCacheOperation.getType());

        JSONArray parameter = new JSONArray();
        parameter.add(command);
        eventBean.setParameters(parameter);
        eventBean.setEventCategory(jCacheOperation.getCategory());
        return eventBean;
    }

    public boolean isPrimitiveType(Class<?> clazz) {
        return (clazz.isPrimitive() && clazz != void.class) || clazz == Double.class || clazz == Float.class || clazz == Long.class ||
                clazz == Integer.class || clazz == Short.class || clazz == Character.class || clazz == Byte.class || clazz == Boolean.class ||
                clazz == String.class;
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
        if (!NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_DETECTION_RXSS_ENABLED, true)) {
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDroppedDueTo().incrementRxssDetectionDeactivated();
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
            eventBean.setHttpResponse(securityMetaData.getResponse());
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
        eventBean.setEventCategory(hashCryptoOperationalBean.getEventCategory());
//        if (eventBean.getSourceMethod().equals(JAVAX_CRYPTO_CIPHER_GETINSTANCE_STRING)
//                || eventBean.getSourceMethod().equals(JAVAX_CRYPTO_CIPHER_GETINSTANCE_STRING_PROVIDER)) {
//            eventBean.setEventCategory(CIPHER);
//        } else if (eventBean.getSourceMethod().equals(JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING)
//                || eventBean.getSourceMethod().equals(JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING_STRING)
//                || eventBean.getSourceMethod().equals(JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING_PROVIDER)) {
//            eventBean.setEventCategory(KEYGENERATOR);
//        } else if (eventBean.getSourceMethod().equals(JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING)
//                || eventBean.getSourceMethod().equals(JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING_STRING)
//                || eventBean.getSourceMethod().equals(JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING_PROVIDER)) {
//            eventBean.setEventCategory(KEYPAIRGENERATOR);
//        }
        return eventBean;
    }

    private JavaAgentEventBean prepareTrustBoundaryEvent(JavaAgentEventBean eventBean,
            TrustBoundaryOperation trustBoundaryOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(trustBoundaryOperationalBean.getKey());
        params.add(JsonConverter.toJSON(trustBoundaryOperationalBean.getValue()));
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
            SecureCookieOperationSet secureCookieOperationalBean) {
        JSONArray params = new JSONArray();
        for (SecureCookieOperationSet.SecureCookieOperation secureCookieOperation : secureCookieOperationalBean.getOperations()) {
            JSONObject cookie = new JSONObject();
            cookie.put(COOKIE_NAME, secureCookieOperation.getName());
            cookie.put(COOKIE_VALUE, secureCookieOperation.getValue());
            cookie.put(COOKIE_IS_SECURE, secureCookieOperation.isSecure());
            cookie.put(COOKIE_IS_HTTP_ONLY, secureCookieOperation.isHttpOnly());
            cookie.put(COOKIE_IS_SAME_SITE_STRICT, secureCookieOperation.isSameSiteStrict());
            params.add(cookie);
        }
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

    private JavaAgentEventBean prepareSQLDbCommandEvent(BatchSQLOperation operation,
            JavaAgentEventBean eventBean) {
        JSONArray params = new JSONArray();
        for (SQLOperation operationalBean : operation.getOperations()) {
            JSONObject query = new JSONObject();
            query.put(QUERY, operationalBean.getQuery());
            if(operationalBean.getParams() != null) {
                query.put(PARAMETERS, new JSONObject(operationalBean.getParams()));
            }
            params.add(query);
        }
        eventBean.setParameters(params);
        eventBean.setEventCategory(operation.getOperations().get(0).getDbName());
        return eventBean;
    }

    private JavaAgentEventBean prepareSQLDbCommandEvent(SQLOperation operation,
                                                        JavaAgentEventBean eventBean) {
        JSONArray params = new JSONArray();
        JSONObject query = new JSONObject();
        query.put(QUERY, operation.getQuery());
        if(operation.getParams() != null) {
            query.put(PARAMETERS, new JSONObject(operation.getParams()));
        }
        if(operation.getObjectParams() != null && !operation.getObjectParams().isEmpty()){
            JSONObject jsonObject = (JSONObject) query.get(PARAMETERS);
            if(jsonObject == null){
                query.put(PARAMETERS, jsonObject);
            }
            for (Map.Entry<String, Object> objParameter : operation.getObjectParams().entrySet()) {
                jsonObject.put(objParameter.getKey(), JsonConverter.toJSON(objParameter.getValue()));
            }
        }
        params.add(query);
        eventBean.setParameters(params);
        if (operation.isStoredProcedureCall()) {
            eventBean.setEventCategory(SQL_STORED_PROCEDURE);
        } else {
            eventBean.setEventCategory(operation.getDbName());
        }

        return eventBean;
    }

    private JavaAgentEventBean prepareSystemCommandEvent(JavaAgentEventBean eventBean,
            ForkExecOperation operationalBean) {
        try {
            List<String> shellScripts = SystemCommandUtils.isShellScriptExecution(operationalBean.getCommand());
            List<String> absolutePaths = SystemCommandUtils.getAbsoluteShellScripts(shellScripts);
            SystemCommandUtils.scriptContent(absolutePaths, operationalBean);
            JSONArray params = new JSONArray();
            params.add(operationalBean.getCommand());
            JSONObject extras = new JSONObject();
            if (operationalBean.getEnvironment() != null) {
                extras.put(SYSCOMMAND_ENVIRONMENT, new JSONObject(operationalBean.getEnvironment()));
            }
            extras.put(SYSCOMMAND_SCRIPT_CONTENT, operationalBean.getScriptContent());
            params.add(extras);
            eventBean.setParameters(params);
            return eventBean;
        } catch (Throwable e){
            e.printStackTrace();
        }
        return eventBean;
    }

    private static JavaAgentEventBean prepareFileEvent(JavaAgentEventBean eventBean,
            FileOperation fileOperationalBean) {
        JSONArray params = new JSONArray();
        params.addAll(fileOperationalBean.getFileName());
        eventBean.setParameters(params);
        if(fileOperationalBean.isGetBooleanAttributesCall()) {
            eventBean.setEventCategory("FILE_EXISTS");
        }
        return eventBean;
    }

    private static JavaAgentEventBean prepareNoSQLEvent(JavaAgentEventBean eventBean,
            NoSQLOperation noSQLOperationalBean) throws ParseException {
        JSONArray params = new JSONArray();
        eventBean.setEventCategory(MONGO);
        JSONParser jsonParser = new JSONParser();
        for (String data : noSQLOperationalBean.getPayload()) {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("payload", jsonParser.parse(data));
            jsonObject.put("payloadType", noSQLOperationalBean.getPayloadType());
            params.add(jsonObject);
        }
        eventBean.setParameters(params);
        return eventBean;
    }

    private static JavaAgentEventBean prepareMemcachedEvent(JavaAgentEventBean eventBean, MemcachedOperation memcachedOperationalBean) {
        JSONArray params = new JSONArray();
        for (Object data : memcachedOperationalBean.getArguments()) {
            params.add(data);
        }
        JSONObject command = new JSONObject();
        command.put(REDIS_ARGUMENTS, params);
        command.put(REDIS_TYPE, memcachedOperationalBean.getType());
        command.put(REDIS_MODE, memcachedOperationalBean.getCommand());
        JSONArray parameter = new JSONArray();
        parameter.add(command);
        eventBean.setParameters(parameter);
        eventBean.setEventCategory(memcachedOperationalBean.getCategory());
        return eventBean;
    }

    private static JavaAgentEventBean prepareDynamoDBEvent(JavaAgentEventBean eventBean, DynamoDBOperation dynamoDBOperation) {
        JSONArray params = new JSONArray();
        eventBean.setEventCategory(dynamoDBOperation.getCategory().toString());
        List<DynamoDBRequest> originalPayloads = dynamoDBOperation.getPayload();
        for (DynamoDBRequest data : originalPayloads) {
            params.add(DynamoDBRequestConverter.convert(dynamoDBOperation.getCategory(), data));
        }
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

            klassName = operation.getStackTrace()[i].getClassName();
            if (VulnerabilityCaseType.SYSTEM_COMMAND.equals(vulnerabilityCaseType)
                    || VulnerabilityCaseType.SQL_DB_COMMAND.equals(vulnerabilityCaseType)
                    || VulnerabilityCaseType.FILE_INTEGRITY.equals(vulnerabilityCaseType)
                    || VulnerabilityCaseType.NOSQL_DB_COMMAND.equals(vulnerabilityCaseType)
                    || VulnerabilityCaseType.FILE_OPERATION.equals(vulnerabilityCaseType)
                    || VulnerabilityCaseType.HTTP_REQUEST.equals(vulnerabilityCaseType)
                    || VulnerabilityCaseType.SYSTEM_EXIT.equals(vulnerabilityCaseType)) {
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
        if (!NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_DETECTION_DESERIALIZATION_ENABLED, true)) {
            return;
        }
        if (ObjectInputStream.class.getName().equals(klassName)
                && StringUtils.equals(operation.getStackTrace()[index].getMethodName(), READ_OBJECT)) {
            eventBean.getMetaData().setTriggerViaDeserialisation(true);
        }
    }

    private void rciTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
        if (!NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_DETECTION_RCI_ENABLED, true)) {
            return;
        }

        if (operation.getStackTrace()[index].getLineNumber() <= 0 && index > 0
                && operation.getStackTrace()[index - 1].getLineNumber() > 0 &&
                StringUtils.isNotBlank(operation.getStackTrace()[index - 1].getFileName())) {
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
        eventBean.setParentId(securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class));
        eventBean.setStartTime(objectBean.getStartTime());
        eventBean.setBlockingProcessingTime((Long) extraInfo.get(BLOCKING_END_TIME) - eventBean.getStartTime());
        eventBean.setApiId(objectBean.getApiID());
        eventBean.setUserAPIInfo(operation.getUserClassEntity().getUserClassElement().getLineNumber(),
                operation.getUserClassEntity().getUserClassElement().getClassName(),
                operation.getUserClassEntity().getUserClassElement().getMethodName());
        eventBean.getLinkingMetadata().put(NR_APM_TRACE_ID, securityMetaData.getCustomAttribute(NR_APM_TRACE_ID, String.class));
        eventBean.getLinkingMetadata().put(NR_APM_SPAN_ID, securityMetaData.getCustomAttribute(NR_APM_SPAN_ID, String.class));
        return eventBean;
    }

    private JavaAgentEventBean prepareEvent(HttpRequest httpRequestBean, AgentMetaData metaData,
            VulnerabilityCaseType vulnerabilityCaseType, K2RequestIdentifier k2RequestIdentifier) {
        if(AgentConfig.getInstance().getAgentMode().getIastScan().getRestricted()) {
            metaData.setSkipScanParameters(AgentConfig.getInstance().getAgentMode().getIastScan().getRestrictionCriteria().getSkipScanParameters());
        }
        JavaAgentEventBean eventBean = new JavaAgentEventBean();
        eventBean.setHttpRequest(httpRequestBean);
        eventBean.setMetaData(metaData);
        eventBean.getMetaData().setAppServerInfo(AppServerInfoHelper.getAppServerInfo());
        eventBean.setCaseType(vulnerabilityCaseType.getCaseType());
        eventBean.setIsAPIBlocked(metaData.isApiBlocked());
        eventBean.setStacktrace(operation.getStackTrace());
        eventBean.setIsIASTRequest(k2RequestIdentifier.getK2Request());
        if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled() && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) {
            eventBean.setIsIASTEnable(true);
        }
        return eventBean;
    }
}