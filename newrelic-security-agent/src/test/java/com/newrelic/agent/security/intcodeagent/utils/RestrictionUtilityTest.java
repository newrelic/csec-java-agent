package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.TraceMetadata;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.policy.AccountInfo;
import com.newrelic.api.agent.security.schema.policy.MappingParameter;
import com.newrelic.api.agent.security.schema.policy.MappingParameters;
import com.newrelic.api.agent.security.schema.policy.RestrictionCriteria;
import com.newrelic.api.agent.security.schema.policy.SkipScan;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.regex.Pattern;

public class RestrictionUtilityTest {

    @Test
    public void skippedApiDetectedNullTest() {
        Assert.assertFalse(RestrictionUtility.skippedApiDetected(new SkipScan(), (HttpRequest) null));
        Assert.assertFalse(RestrictionUtility.skippedApiDetected(null, Mockito.mock(HttpRequest.class)));
        Assert.assertFalse(RestrictionUtility.skippedApiDetected(new SkipScan(), Mockito.mock(HttpRequest.class)));
    }

    @Test
    public void skippedApiDetectedTest() {
        MockedStatic<NewRelic> nrAgent = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrAgent.when(NewRelic.getAgent()::getTraceMetadata).thenReturn(Mockito.mock(TraceMetadata.class));
            nrAgent.when(NewRelic.getAgent().getTraceMetadata()::getTraceId).thenReturn("1");
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.setUrl("/url");

            SkipScan skipScan = new SkipScan();
            skipScan.getApiRoutes().add(Pattern.compile(".*"));

            IastExclusionUtils.getInstance().registerSkippedTrace("1");

            Assert.assertTrue(RestrictionUtility.skippedApiDetected(skipScan, httpRequest));
        } finally {
            nrAgent.clearInvocations();
            nrAgent.reset();
            nrAgent.close();
        }
    }

    @Test
    public void skippedApiDetected1Test() {
        MockedStatic<NewRelic> nrAgent = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrAgent.when(NewRelic.getAgent()::getTraceMetadata).thenReturn(Mockito.mock(TraceMetadata.class));
            nrAgent.when(NewRelic.getAgent().getTraceMetadata()::getTraceId).thenReturn("3");
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.setUrl("/url");

            SkipScan skipScan = new SkipScan();
            skipScan.getApiRoutes().add(Pattern.compile(".*"));

            IastExclusionUtils.getInstance().registerSkippedTrace("1");

            Assert.assertTrue(RestrictionUtility.skippedApiDetected(skipScan, httpRequest));
        } finally {
            nrAgent.clearInvocations();
            nrAgent.reset();
            nrAgent.close();
        }
    }

    @Test
    public void skippedApiDetected2Test() {
        MockedStatic<NewRelic> nrAgent = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrAgent.when(NewRelic.getAgent()::getTraceMetadata).thenReturn(Mockito.mock(TraceMetadata.class));
            nrAgent.when(NewRelic.getAgent().getTraceMetadata()::getTraceId).thenReturn("41");
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.setUrl("/url");

            SkipScan skipScan = new SkipScan();
            skipScan.getApiRoutes().add(Pattern.compile("[a-b]"));

            Assert.assertFalse(RestrictionUtility.skippedApiDetected(skipScan, httpRequest));
        } finally {
            nrAgent.clearInvocations();
            nrAgent.reset();
            nrAgent.close();
        }
    }

    @Test
    public void hasValidAccountIdTest() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, null));
    }

    @Test
    public void hasValidAccountId_PathParam1_Test() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1?name=ish&accountId=1");
        request.getHeaders().put("accountId", "account-1");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_JsonBody1_Test() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account-i1");
        request.setContentType("application/json");
        request.getBody().append("{\"person\":{\"name\":\"ishi\",\"accountId\":\"1\"}}");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_XmlBody1_Test() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.setContentType("application/xml");
        request.getBody().append("<person><name>ishi</name><accountId>1</accountId></person>");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_UrlEncoded1_Test() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_ParameterMap1_Test() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.getParameterMap().put("accountId", new String[]{"1"});
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_PathParam2_Test() {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1?name=ish&accountId=1");
        request.getHeaders().put("accountId", "account-1");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_JsonBody2_Test() {
        final RestrictionCriteria restrictionCriteria = getRestrictionCriteria(false, true, false, false);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account-i1");
        request.setContentType("application/json");
        request.getBody().append("{\"person\":{\"name\":\"ishi\",\"accountId\":\"1\"}}");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_XmlBody2_Test() {
        RestrictionCriteria restrictionCriteria = getRestrictionCriteria(false, true, false, false);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.setContentType("application/xml");
        request.getBody().append("<person><name>ishi</name><accountId>1</accountId></person>");
        Assert.assertFalse(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_UrlEncoded2_Test() {
        RestrictionCriteria restrictionCriteria = getRestrictionCriteria(false, true, false, false);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertTrue(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_ParameterMap2_Test() {
        RestrictionCriteria restrictionCriteria = getRestrictionCriteria(false, true, false, false);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.getParameterMap().put("accountId", new String[]{"1"});
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertTrue(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_Query_Test() {
        RestrictionCriteria restrictionCriteria = getRestrictionCriteria(true, false, false, false);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.getParameterMap().put("accountId", new String[]{"1"});
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertTrue(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_Header_Test() {
        RestrictionCriteria restrictionCriteria = getRestrictionCriteria(false, false, true, false);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/id-1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.getParameterMap().put("accountId", new String[]{"1"});
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertTrue(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    @Test
    public void hasValidAccountId_Path_Test() {
        RestrictionCriteria restrictionCriteria = getRestrictionCriteria(false, false, false, true);

        HttpRequest request = new HttpRequest();
        request.setUrl("/url/1;name=ish&accountId=1");
        request.getHeaders().put("accountId", "1;sub-account=i1");
        request.getParameterMap().put("accountId", new String[]{"1"});
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("name=ishi&accountId=1");
        Assert.assertTrue(RestrictionUtility.hasValidAccountId(restrictionCriteria, request));
    }

    private static RestrictionCriteria getRestrictionCriteria(boolean header, boolean body, boolean query, boolean path) {
        RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(Collections.singletonList("1")));
        restrictionCriteria.setMappingParameters(
                new MappingParameters(
                        new MappingParameter(header, Collections.singletonList("accountId")),
                        new MappingParameter(body, Collections.singletonList("accountId")),
                        new MappingParameter(query, Collections.singletonList("accountId")),
                        new MappingParameter(path, Collections.singletonList("accountId"))
                ));
        return restrictionCriteria;
    }
}
