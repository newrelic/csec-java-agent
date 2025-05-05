package com.newrelic.agent.security.instrumentator.dispatcher;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.exceptions.RestrictionModeException;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CustomerInfo;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IdentifierEnvs;
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
import com.newrelic.api.agent.security.schema.policy.ScanSchedule;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;

public class DispatcherTest {

    @BeforeClass
    public static void beforeClass() throws RestrictionModeException {
        CollectorConfig collectorConfig = Mockito.mock(CollectorConfig.class);
        Identifier identifier = new Identifier();
        identifier.setKind(IdentifierEnvs.HOST);
        AgentInfo.getInstance().setIdentifier(identifier);
        FileLoggerThreadPool.getInstance().initialiseLogger();
        AgentInfo.initialiseLogger();
        AgentConfig.getInstance().setConfig(new CollectorConfig());
        AgentConfig.getInstance().getConfig().setCustomerInfo(new CustomerInfo());
        AgentConfig.getInstance().getConfig().getCustomerInfo().setAccountId("1");

        AgentConfig.getInstance().instantiate();
        AgentConfig.getInstance().getAgentMode().setScanSchedule(new ScanSchedule());

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
        Path fileName = Paths.get(String.format("/tmp/tmp%s.sh", UUID.randomUUID()));
        Files.createFile(fileName);
        Files.write(fileName, "echo 'hello'".getBytes());

        ForkExecOperation systemCmd = Mockito.mock(ForkExecOperation.class);
        doReturn(fileName.toString()).when(systemCmd).getCommand();
        doReturn(new HashMap<>()).when(systemCmd).getScriptContent();
        doReturn(new HashMap<>()).when(systemCmd).getEnvironment();
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, systemCmd, VulnerabilityCaseType.SYSTEM_COMMAND);

        Dispatcher dispatcher = new Dispatcher(systemCmd, metaData);
        dispatcher.call();

        Mockito.verify(systemCmd, atLeastOnce()).getCaseType();
        Mockito.verify(systemCmd, atLeastOnce()).getCommand();
        Mockito.verify(systemCmd, atLeastOnce()).getEnvironment();
        Mockito.verify(systemCmd, atLeastOnce()).getUserClassEntity();
        Mockito.verify(systemCmd, atLeastOnce()).getScriptContent();

        Mockito.verify(metaData, atLeastOnce()).getRequest();
        Mockito.verify(metaData, atLeastOnce()).getMetaData();

        Mockito.clearInvocations(systemCmd, metaData);
        Mockito.clearInvocations();
        Mockito.clearAllCaches();
        Files.deleteIfExists(fileName);
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

        SQLOperation op = Mockito.mock(SQLOperation.class);
        Mockito.doReturn(Collections.singletonMap("key","val")).when(op).getParams();
        Mockito.doReturn(Collections.singletonList(op)).when(sqlOperation).getOperations();
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
        SQLOperation op = Mockito.mock(SQLOperation.class);
        Mockito.doReturn(Collections.singletonMap("key","val")).when(op).getParams();
        Mockito.doReturn(Collections.singletonList(op)).when(noSqlOperation).getOperations();
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
        Mockito.doReturn(Collections.singletonList("payload")).when(noSqlOperation).getPayload();
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
        SecureCookieOperationSet operationSet = Mockito.mock(SecureCookieOperationSet.class);
        SecureCookieOperationSet.SecureCookieOperation cookieOperation = Mockito.mock(SecureCookieOperationSet.SecureCookieOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);

        Mockito.doReturn(Collections.singleton(cookieOperation)).when(operationSet).getOperations();
        setMocks(metaData, operationSet, VulnerabilityCaseType.SECURE_COOKIE);

        Dispatcher dispatcher = new Dispatcher(operationSet, metaData);
        dispatcher.call();

        Mockito.verify(operationSet, atLeastOnce()).getCaseType();
        Mockito.verify(operationSet, atLeastOnce()).getOperations();
        Mockito.verify(cookieOperation, atLeastOnce()).getName();
        Mockito.verify(cookieOperation, atLeastOnce()).getValue();
        Mockito.verify(cookieOperation, atLeastOnce()).isSecure();
        Mockito.verify(cookieOperation, atLeastOnce()).isHttpOnly();

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

    @Test
    public void redisOperationTest() throws Exception {
        RedisOperation redisOperation = Mockito.mock(RedisOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, redisOperation, VulnerabilityCaseType.CACHING_DATA_STORE);

        Dispatcher dispatcher = new Dispatcher(redisOperation, metaData);
        dispatcher.call();

        Mockito.verify(redisOperation, atLeastOnce()).getCaseType();
        Mockito.verify(redisOperation, atLeastOnce()).getArguments();
        Mockito.verify(redisOperation, atLeastOnce()).getMode();
        Mockito.verify(redisOperation, atLeastOnce()).getType();

        Mockito.clearInvocations(redisOperation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }

    @Test
    public void jCacheOperationTest() throws Exception {
        JCacheOperation operation = Mockito.mock(JCacheOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, operation, VulnerabilityCaseType.CACHING_DATA_STORE);

        Dispatcher dispatcher = new Dispatcher(operation, metaData);
        dispatcher.call();

        Mockito.verify(operation, atLeastOnce()).getCaseType();
        Mockito.verify(operation, atLeastOnce()).getArguments();
        Mockito.verify(operation, atLeastOnce()).getCategory();
        Mockito.verify(operation, atLeastOnce()).getType();

        Mockito.clearInvocations(operation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }

    @Test
    public void memcachedOperationTest() throws Exception {
        MemcachedOperation operation = Mockito.mock(MemcachedOperation.class);
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, operation, VulnerabilityCaseType.CACHING_DATA_STORE);

        Dispatcher dispatcher = new Dispatcher(operation, metaData);
        dispatcher.call();

        Mockito.verify(operation, atLeastOnce()).getCaseType();
        Mockito.verify(operation, atLeastOnce()).getArguments();
        Mockito.verify(operation, atLeastOnce()).getCategory();
        Mockito.verify(operation, atLeastOnce()).getType();

        Mockito.clearInvocations(operation);
        Mockito.clearInvocations(metaData);
        Mockito.clearAllCaches();
    }


    @Test
    public void testSolrDbOperation() throws Exception {
        SolrDbOperation operation = Mockito.mock(SolrDbOperation.class);
        Mockito.doReturn(Thread.currentThread().getStackTrace()).when(operation).getStackTrace();
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, operation, VulnerabilityCaseType.SOLR_DB_REQUEST);

        Dispatcher dispatcher = new Dispatcher(operation, metaData);
        dispatcher.call();
        Assert.assertNotNull(dispatcher.getSecurityMetaData());
        Assert.assertNotNull(dispatcher.getOperation());
        Assert.assertNull(dispatcher.getExitEventBean());

        Mockito.verify(operation, atLeastOnce()).getCaseType();
        Mockito.verify(operation, atLeastOnce()).getCollection();
        Mockito.verify(operation, atLeastOnce()).getMethod();
        Mockito.verify(operation, atLeastOnce()).getConnectionURL();
        Mockito.verify(operation, atLeastOnce()).getPath();
        Mockito.verify(operation, atLeastOnce()).getParams();
        Mockito.verify(operation, atLeastOnce()).getDocuments();

        Mockito.clearInvocations(operation);
        Mockito.clearAllCaches();
    }

    @Test
    public void testRXSSOperation() throws Exception {
        RXSSOperation operation = Mockito.mock(RXSSOperation.class);
        Mockito.doReturn(Thread.currentThread().getStackTrace()).when(operation).getStackTrace();
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);

        setMocks(metaData, operation, VulnerabilityCaseType.REFLECTED_XSS);

        Dispatcher dispatcher = new Dispatcher(operation, metaData);
        dispatcher.call();
        Assert.assertNotNull(dispatcher.getSecurityMetaData());
        Assert.assertNotNull(dispatcher.getOperation());
        Assert.assertNull(dispatcher.getExitEventBean());

        Mockito.verify(operation, atLeastOnce()).getCaseType();

        Mockito.clearInvocations(operation);
        Mockito.clearAllCaches();
    }

    @Test
    public void testProcessStackTrace() throws Exception {
        SSRFOperation ssrfOperation = Mockito.mock(SSRFOperation.class);
        Mockito.doReturn(Thread.currentThread().getStackTrace()).when(ssrfOperation).getStackTrace();
        SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
        setMocks(metaData, ssrfOperation, VulnerabilityCaseType.HTTP_REQUEST);

        Dispatcher dispatcher = new Dispatcher(ssrfOperation, metaData);
        dispatcher.call();
        Assert.assertNotNull(dispatcher.getSecurityMetaData());
        Assert.assertNotNull(dispatcher.getOperation());
        Assert.assertNull(dispatcher.getExitEventBean());

        Mockito.verify(ssrfOperation, atLeastOnce()).getStackTrace();
        Mockito.clearInvocations(ssrfOperation);
        Mockito.clearAllCaches();
    }

    @Test
    public void testExitEvent() throws Exception {
        ExitEventBean exitEventBean = Mockito.mock(ExitEventBean.class);

        Dispatcher dispatcher = new Dispatcher(exitEventBean);
        dispatcher.call();
        Assert.assertNull(dispatcher.getSecurityMetaData());
        Assert.assertNull(dispatcher.getOperation());
        Assert.assertNotNull(dispatcher.getExitEventBean());

        Mockito.clearAllCaches();
    }



    private void setMocks(SecurityMetaData metaData, AbstractOperation operation, VulnerabilityCaseType caseType) {
        doReturn(caseType).when(operation).getCaseType();
        doReturn(Mockito.mock(AgentMetaData.class)).when(metaData).getMetaData();
        HttpRequest httpRequest = new HttpRequest();
        HttpResponse response = new HttpResponse();
        httpRequest.setUrl("/url"); httpRequest.getBody().append("hello");

        doReturn(httpRequest).when(metaData).getRequest();
        doReturn(response).when(metaData).getResponse();
        doReturn(Mockito.mock(K2RequestIdentifier.class)).when(metaData).getFuzzRequestIdentifier();
        String header = "header";
        doReturn(header).when(metaData).getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
        doReturn(header).when(metaData).getCustomAttribute("trace.id", String.class);
        doReturn(header).when(metaData).getCustomAttribute("span.id", String.class);
        UserClassEntity entity = new UserClassEntity();
        entity.setUserClassElement(Thread.currentThread().getStackTrace()[1]);
        doReturn(entity).when(operation).getUserClassEntity();
    }

}
