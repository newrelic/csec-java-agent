package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashSet;

public class CallbackUtilsTest {

    @Test
    public void checkForReflectedXSS () {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }
    @Test
    public void checkForReflectedXSS1 () {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }
    @Test
    public void checkForReflectedXSS2 () {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }

    @Test
    public void urlDecode() {
        Assert.assertEquals(StringUtils.EMPTY, CallbackUtils.urlDecode(StringUtils.EMPTY));
        Assert.assertEquals("  ", CallbackUtils.urlDecode("  "));
        Assert.assertEquals("<script>", CallbackUtils.urlDecode("<script>"));
        Assert.assertEquals("<script>", CallbackUtils.urlDecode("%3Cscript%3E"));
    }
    @Test
    public void getXSSConstructs() {

    }
}
