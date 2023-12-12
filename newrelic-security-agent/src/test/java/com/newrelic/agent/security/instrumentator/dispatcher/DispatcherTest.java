package com.newrelic.agent.security.instrumentator.dispatcher;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IdentifierEnvs;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.UserClassEntity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.*;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;

public class DispatcherTest {

    private final String CLASS_NAME = "className";
    private final String METHOD_NAME = "methodName";
    private final String header = "header";

    @Mock
    private FileLoggerThreadPool logger;


    @BeforeClass
    public static void beforeClass() {
        CollectorConfig collectorConfig = Mockito.mock(CollectorConfig.class);
        Identifier identifier = new Identifier();
        identifier.setKind(IdentifierEnvs.HOST);
        AgentInfo.getInstance().setIdentifier(identifier);
        AgentInfo.getInstance().generateAppInfo(collectorConfig);
        AgentInfo.getInstance().initialiseHC();
    }

    @Test
    public void testProcessNullEventTest() throws Exception {

        Dispatcher dispatcher = new Dispatcher(null, Mockito.mock(SecurityMetaData.class));
        Assert.assertNull(dispatcher.call());
    }
    @Test
    public void testProcessFileOpTest() throws Exception {
        FileOperation fileOp = Mockito.mock(FileOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, fileOp, VulnerabilityCaseType.FILE_OPERATION);

        Dispatcher dispatcher = new Dispatcher(fileOp, metaData);
        dispatcher.call();

        Mockito.verify(fileOp, atLeastOnce()).getCaseType();
        Mockito.verify(fileOp, atLeastOnce()).getFileName();
        Mockito.verify(fileOp, atLeastOnce()).getUserClassEntity();
        Mockito.verify(fileOp, atLeastOnce()).isGetBooleanAttributesCall();


        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(fileOp);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessRXSSTest() throws Exception {
        RXSSOperation rxss = Mockito.mock(RXSSOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, rxss, VulnerabilityCaseType.REFLECTED_XSS);

        Dispatcher dispatcher = new Dispatcher(rxss, metaData);
        dispatcher.call();

        Mockito.verify(rxss, atLeastOnce()).getCaseType();
        Mockito.verify(rxss, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getResponse();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(rxss);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }

    @Test
    public void testProcessRCETest() throws Exception {
        ForkExecOperation systemCmd = Mockito.mock(ForkExecOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, systemCmd, VulnerabilityCaseType.SYSTEM_COMMAND);

        Dispatcher dispatcher = new Dispatcher(systemCmd, metaData);
        dispatcher.call();

        Mockito.verify(systemCmd, atLeastOnce()).getCaseType();
        Mockito.verify(systemCmd, atLeastOnce()).getCommand();
        Mockito.verify(systemCmd, atLeastOnce()).getEnvironment();
        Mockito.verify(systemCmd, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(systemCmd);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessSQLTest() throws Exception {
        SQLOperation sqlOperation = Mockito.mock(SQLOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, sqlOperation, VulnerabilityCaseType.SQL_DB_COMMAND);

        Dispatcher dispatcher = new Dispatcher(sqlOperation, metaData);
        dispatcher.call();

        Mockito.verify(sqlOperation, atLeastOnce()).getCaseType();
        Mockito.verify(sqlOperation, atLeastOnce()).getDbName();
        Mockito.verify(sqlOperation, atLeastOnce()).getParams();
        Mockito.verify(sqlOperation, atLeastOnce()).getUserClassEntity();
        Mockito.verify(sqlOperation, atLeastOnce()).getQuery();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(sqlOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessBatchSQLTest() throws Exception {
        BatchSQLOperation sqlOperation = Mockito.mock(BatchSQLOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, sqlOperation, VulnerabilityCaseType.SQL_DB_COMMAND);

        Dispatcher dispatcher = new Dispatcher(sqlOperation, metaData);
        dispatcher.call();

        Mockito.verify(sqlOperation, atLeastOnce()).getCaseType();
        Mockito.verify(sqlOperation, atLeastOnce()).getOperations();
        Mockito.verify(sqlOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(sqlOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }

    @Test
    public void testProcessNoSQLTest() throws Exception {
        SQLOperation noSqlOperation = Mockito.mock(SQLOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, noSqlOperation, VulnerabilityCaseType.NOSQL_DB_COMMAND);

        Dispatcher dispatcher = new Dispatcher(noSqlOperation, metaData);
        dispatcher.call();

        Mockito.verify(noSqlOperation, atLeastOnce()).getCaseType();
        Mockito.verify(noSqlOperation, atLeastOnce()).getDbName();
        Mockito.verify(noSqlOperation, atLeastOnce()).getParams();
        Mockito.verify(noSqlOperation, atLeastOnce()).getUserClassEntity();
        Mockito.verify(noSqlOperation, atLeastOnce()).getQuery();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(noSqlOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessBatchNoSQLTest() throws Exception {
        BatchSQLOperation noSqlOperation = Mockito.mock(BatchSQLOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, noSqlOperation, VulnerabilityCaseType.NOSQL_DB_COMMAND);

        Dispatcher dispatcher = new Dispatcher(noSqlOperation, metaData);
        dispatcher.call();

        Mockito.verify(noSqlOperation, atLeastOnce()).getCaseType();
        Mockito.verify(noSqlOperation, atLeastOnce()).getOperations();
        Mockito.verify(noSqlOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(noSqlOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }

    @Test
    public void testProcessNoSQLDBTest() throws Exception {
        NoSQLOperation noSqlOperation = Mockito.mock(NoSQLOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, noSqlOperation, VulnerabilityCaseType.NOSQL_DB_COMMAND);

        Dispatcher dispatcher = new Dispatcher(noSqlOperation, metaData);
        dispatcher.call();

        Mockito.verify(noSqlOperation, atLeastOnce()).getCaseType();
        Mockito.verify(noSqlOperation, atLeastOnce()).getPayload();
        Mockito.verify(noSqlOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(noSqlOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessDynamoTest() throws Exception {
        DynamoDBOperation dynamoDBOperation = Mockito.mock(DynamoDBOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, dynamoDBOperation, VulnerabilityCaseType.NOSQL_DB_COMMAND);
        doReturn(DynamoDBOperation.Category.DQL).when(dynamoDBOperation).getCategory();

        Dispatcher dispatcher = new Dispatcher(dynamoDBOperation, metaData);
        dispatcher.call();

        Mockito.verify(dynamoDBOperation, atLeastOnce()).getCaseType();
        Mockito.verify(dynamoDBOperation, atLeastOnce()).getPayload();
        Mockito.verify(dynamoDBOperation, atLeastOnce()).getCategory();
        Mockito.verify(dynamoDBOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(dynamoDBOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessFileIntegrityTest() throws Exception {
        FileIntegrityOperation fileIntegrityOperation = Mockito.mock(FileIntegrityOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, fileIntegrityOperation, VulnerabilityCaseType.FILE_INTEGRITY);

        Dispatcher dispatcher = new Dispatcher(fileIntegrityOperation, metaData);
        dispatcher.call();

        Mockito.verify(fileIntegrityOperation, atLeastOnce()).getCaseType();
        Mockito.verify(fileIntegrityOperation, atLeastOnce()).getFileName();
        Mockito.verify(fileIntegrityOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(fileIntegrityOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessLdapTest() throws Exception {
        LDAPOperation ldapOperation = Mockito.mock(LDAPOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, ldapOperation, VulnerabilityCaseType.LDAP);

        Dispatcher dispatcher = new Dispatcher(ldapOperation, metaData);
        dispatcher.call();

        Mockito.verify(ldapOperation, atLeastOnce()).getCaseType();
        Mockito.verify(ldapOperation, atLeastOnce()).getFilter();
        Mockito.verify(ldapOperation, atLeastOnce()).getName();
        Mockito.verify(ldapOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(ldapOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessRandomTest() throws Exception {
        RandomOperation randomOperation = Mockito.mock(RandomOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, randomOperation, VulnerabilityCaseType.RANDOM);

        Dispatcher dispatcher = new Dispatcher(randomOperation, metaData);
        dispatcher.call();

        Mockito.verify(randomOperation, atLeastOnce()).getCaseType();
        Mockito.verify(randomOperation, atLeastOnce()).getClassName();
        Mockito.verify(randomOperation, atLeastOnce()).getEventCatgory();
        Mockito.verify(randomOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(randomOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessSSRFTest() throws Exception {
        SSRFOperation ssrfOperation = Mockito.mock(SSRFOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, ssrfOperation, VulnerabilityCaseType.HTTP_REQUEST);

        Dispatcher dispatcher = new Dispatcher(ssrfOperation, metaData);
        dispatcher.call();

        Mockito.verify(ssrfOperation, atLeastOnce()).getCaseType();
        Mockito.verify(ssrfOperation, atLeastOnce()).isJNDILookup();
        Mockito.verify(ssrfOperation, atLeastOnce()).getArg();
        Mockito.verify(ssrfOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(ssrfOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessXPathTest() throws Exception {
        XPathOperation xPathOperation = Mockito.mock(XPathOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);

        setMocks(metaData, xPathOperation, VulnerabilityCaseType.XPATH);

        Dispatcher dispatcher = new Dispatcher(xPathOperation, metaData);
        dispatcher.call();

        Mockito.verify(xPathOperation, atLeastOnce()).getCaseType();
        Mockito.verify(xPathOperation, atLeastOnce()).getExpression();
        Mockito.verify(xPathOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(xPathOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessSecureTest() throws Exception {
        SecureCookieOperation cookieOperation = Mockito.mock(SecureCookieOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, cookieOperation, VulnerabilityCaseType.SECURE_COOKIE);

        Dispatcher dispatcher = new Dispatcher(cookieOperation, metaData);
        dispatcher.call();

        Mockito.verify(cookieOperation, atLeastOnce()).getCaseType();
        Mockito.verify(cookieOperation, atLeastOnce()).getValue();
        Mockito.verify(cookieOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(cookieOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessTrustBoundaryTest() throws Exception {
        TrustBoundaryOperation trustBoundaryOperation = Mockito.mock(TrustBoundaryOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, trustBoundaryOperation, VulnerabilityCaseType.TRUSTBOUNDARY);

        Dispatcher dispatcher = new Dispatcher(trustBoundaryOperation, metaData);
        dispatcher.call();

        Mockito.verify(trustBoundaryOperation, atLeastOnce()).getCaseType();
        Mockito.verify(trustBoundaryOperation, atLeastOnce()).getKey();
        Mockito.verify(trustBoundaryOperation, atLeastOnce()).getValue();
        Mockito.verify(trustBoundaryOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(trustBoundaryOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessCryptoTest() throws Exception {
        HashCryptoOperation cryptoOperation = Mockito.mock(HashCryptoOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, cryptoOperation, VulnerabilityCaseType.CRYPTO);

        Dispatcher dispatcher = new Dispatcher(cryptoOperation, metaData);
        dispatcher.call();

        Mockito.verify(cryptoOperation, atLeastOnce()).getCaseType();
        Mockito.verify(cryptoOperation, atLeastOnce()).getName();
        Mockito.verify(cryptoOperation, atLeastOnce()).getEventCategory();
        Mockito.verify(cryptoOperation, atLeastOnce()).getProvider();
        Mockito.verify(cryptoOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(cryptoOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessHashTest() throws Exception {
        HashCryptoOperation hashCryptoOperation = Mockito.mock(HashCryptoOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, hashCryptoOperation, VulnerabilityCaseType.HASH);

        Dispatcher dispatcher = new Dispatcher(hashCryptoOperation, metaData);
        dispatcher.call();

        Mockito.verify(hashCryptoOperation, atLeastOnce()).getCaseType();
        Mockito.verify(hashCryptoOperation, atLeastOnce()).getName();
        Mockito.verify(hashCryptoOperation, atLeastOnce()).getProvider();
        Mockito.verify(hashCryptoOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(hashCryptoOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessJSTest() throws Exception {
        JSInjectionOperation jsInjectionOperation = Mockito.mock(JSInjectionOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, jsInjectionOperation, VulnerabilityCaseType.JAVASCRIPT_INJECTION);

        Dispatcher dispatcher = new Dispatcher(jsInjectionOperation, metaData);
        dispatcher.call();

        Mockito.verify(jsInjectionOperation, atLeastOnce()).getCaseType();
        Mockito.verify(jsInjectionOperation, atLeastOnce()).getJavaScriptCode();
        Mockito.verify(jsInjectionOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(jsInjectionOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    @Test
    public void testProcessXQueryTest() throws Exception {
        XQueryOperation xQueryOperation = Mockito.mock(XQueryOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, xQueryOperation, VulnerabilityCaseType.XQUERY_INJECTION);

        Dispatcher dispatcher = new Dispatcher(xQueryOperation, metaData);
        dispatcher.call();

        Mockito.verify(xQueryOperation, atLeastOnce()).getCaseType();
        Mockito.verify(xQueryOperation, atLeastOnce()).getExpression();
        Mockito.verify(xQueryOperation, atLeastOnce()).getUserClassEntity();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(xQueryOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }
    private void setMocks(SecurityMetaData metaData, AbstractOperation operation, VulnerabilityCaseType caseType) {
        doReturn(caseType).when(operation).getCaseType();
        doReturn(Mockito.mock(AgentMetaData.class)).when(metaData).getMetaData();
        doReturn(Mockito.mock(HttpRequest.class)).when(metaData).getRequest();
        doReturn(Mockito.mock(HttpResponse.class)).when(metaData).getResponse();
        doReturn(Mockito.mock(K2RequestIdentifier.class)).when(metaData).getFuzzRequestIdentifier();
        doReturn(header).when(metaData).getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
        doReturn(header).when(metaData).getCustomAttribute("trace.id", String.class);
        doReturn(header).when(metaData).getCustomAttribute("span.id", String.class);
        UserClassEntity entity = new UserClassEntity();
        entity.setUserClassElement(Thread.currentThread().getStackTrace()[1]);
        doReturn(entity).when(operation).getUserClassEntity();
    }

}
